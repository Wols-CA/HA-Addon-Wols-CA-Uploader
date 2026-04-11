#include "include/MqttModule.hpp"
#include "include/ApplicationContext.hpp"
#include "include/ConfigManager.hpp"
#include "include/GlobalUtilities.hpp"
#include "include/SecurityManager.hpp"
#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>

#ifdef _WIN32
namespace mqtt
{
const std::string message::EMPTY_STR = "";
}
#endif

// Centralized Strings (Ready to be moved to LanguagePack/ConfigManager)
const std::string MSG_DEBUG_START = "START: ";
const std::string MSG_DEBUG_END   = "END: ";
const std::string MSG_FATAL_URL   = "FATAL: Broker URL is empty! Check JSON config.";
const std::string MSG_CONN_SUCC   = "Connected to Broker successfully.";

MqttModule::MqttModule( ApplicationContext &context ) : IModule( context )
{
    m_instanceId = GlobalUtils::SanitizeTopic( m_appContext.config->GetString( ConfigKey::LocalServerName ) );
    m_mailboxId  = m_appContext.config->GetString( ConfigKey::MailboxID );

    if ( m_mailboxId.empty() )
    {
        m_mailboxId = "88889999";
    }
}

MqttModule::~MqttModule() { Stop(); }

void MqttModule::Start()
{
    if ( IsActive() ) return;
    m_stopRequested = false;
    m_lastKeyBroadcast = std::chrono::steady_clock::now();
    m_workerThread  = std::thread( &MqttModule::InternalRun, this );
}

void MqttModule::Stop()
{
    m_stopRequested = true;
    if ( m_workerThread.joinable() ) m_workerThread.join();
}

void MqttModule::SubscribeToSecureMailbox()
{
    if ( !m_client || !m_client->is_connected() ) return;

    // 1. Subscribe to the hashed mailbox channels
    std::string requestTopic = GlobalUtils::GetMailboxPath( m_mailboxId, "requests" );
    m_client->subscribe( requestTopic, 1 );

    std::string configTopic = GlobalUtils::GetMailboxPath( m_mailboxId, m_instanceId + "_config" );
    m_client->subscribe( configTopic, 1 );

    // 2. Subscribe to the Front Door (Handshake topics)
    m_client->subscribe( "wols_ca_mqtt/admin/request_key", 1 );
    m_client->subscribe( "wols_ca_mqtt/admin/encrypted_credentials", 1 );
    m_client->subscribe( "wols_ca_mqtt/admin/uploader_verify", 1 );

    GlobalUtils::LogToConsole( "MQTT", "Subscribed to secure scrambled mailbox path and handshake topics." );
}

// ==============================================================================
// WOLS CA HANDSHAKE: STEP A
// ==============================================================================
void MqttModule::StepA_Broadcast_PublicKey()
{
    bool isDebug = (m_appContext.config->GetString(ConfigKey::LogModus) == "DEBUG");
    if (isDebug) GlobalUtils::LogToConsole("DEBUG", MSG_DEBUG_START + "StepA_Broadcast_PublicKey");

    if ( m_client && m_client->is_connected() )
    {
        std::string pubKey = m_appContext.security->GetPublicKeyPem();
        m_client->publish( "wols_ca_mqtt/keys/public", pubKey, 1, false );
    }

    if (isDebug) GlobalUtils::LogToConsole("DEBUG", MSG_DEBUG_END + "StepA_Broadcast_PublicKey");
}

// ==============================================================================
// WOLS CA HANDSHAKE: STEP B
// ==============================================================================
void MqttModule::StepB_Process_Credentials( const std::string &payload )
{
    bool isDebug = (m_appContext.config->GetString(ConfigKey::LogModus) == "DEBUG");
    if (isDebug) GlobalUtils::LogToConsole("DEBUG", MSG_DEBUG_START + "StepB_Process_Credentials");

    std::string decrypted = m_appContext.security->RsaDecrypt( payload );
    if ( decrypted.empty() )
    {
        GlobalUtils::LogToConsole( "Security", "Step B Failed: Decryption error." );
        m_client->publish( "wols_ca_mqtt/admin/password_ack", "NACK", 1, false );
        if (isDebug) GlobalUtils::LogToConsole("DEBUG", MSG_DEBUG_END + "StepB_Process_Credentials (FAIL)");
        return;
    }

    try
    {
        auto jsonPayload = nlohmann::json::parse(decrypted);
        std::string incUrl  = jsonPayload.value("url", "");
        std::string incUser = jsonPayload.value("user", "");
        std::string incPass = jsonPayload.value("pass", "");

        std::string curUrl  = m_appContext.config->GetString( ConfigKey::MqttUrl );
        std::string curUser = m_appContext.config->GetString( ConfigKey::MqttUserId );
        std::string curPass = m_appContext.config->GetString( ConfigKey::MqttPassword );

        // Self-Healing Config Check
        if ( incUrl != curUrl || incUser != curUser || incPass != curPass )
        {
            GlobalUtils::LogToConsole("Security", "Credentials mismatch. Testing new credentials from Uploader...");
            if ( TestNewCredentials(incUrl, incUser, incPass) )
            {
                GlobalUtils::LogToConsole("Security", "New credentials valid. Updating local config.");
                UpdateAndReconnect(incUrl, incUser, incPass);
            }
            else
            {
                GlobalUtils::LogToConsole("Security", "New credentials failed connection test. Sending NACK.");
                m_client->publish( "wols_ca_mqtt/admin/password_ack", "NACK", 1, false );
                return;
            }
        }

        // Generate Set B and prepare payload
        std::string newPubKey, newPrivKey;
        GlobalUtils::GenerateRsaKeyPair( newPubKey, newPrivKey );

        nlohmann::json responseJson;
        responseJson["url"]  = curUrl;
        responseJson["user"] = curUser;
        responseJson["pass"] = curPass;
        responseJson["new_pub_key"] = newPubKey;

        std::string jsonStr = responseJson.dump();
        // Wols CA Standard: Sign with the current password as Proof of Decryption
        std::string signature = GlobalUtils::Sha256(jsonStr + curPass); 
        
        nlohmann::json secureEnvelope;
        secureEnvelope["data"] = jsonStr;
        secureEnvelope["signature"] = signature;

        m_client->publish( "wols_ca_mqtt/admin/service_verify", secureEnvelope.dump(), 1, false );

        // Store Set B temporarily until Step C validation
        m_appContext.security->SetTemporaryKeys(newPubKey, newPrivKey);
    }
    catch (...)
    {
        m_client->publish( "wols_ca_mqtt/admin/password_ack", "NACK", 1, false );
    }

    if (isDebug) GlobalUtils::LogToConsole("DEBUG", MSG_DEBUG_END + "StepB_Process_Credentials");
}

// ==============================================================================
// WOLS CA HANDSHAKE: STEP C
// ==============================================================================
void MqttModule::StepC_Process_UploaderVerify( const std::string &payload )
{
    bool isDebug = (m_appContext.config->GetString(ConfigKey::LogModus) == "DEBUG");
    if (isDebug) GlobalUtils::LogToConsole("DEBUG", MSG_DEBUG_START + "StepC_Process_UploaderVerify");

    // Decrypt with Private Key B (from Temporary Keys)
    std::string decrypted = m_appContext.security->RsaDecryptTemp( payload );
    
    if ( !decrypted.empty() && decrypted.find("WolsCA_Uploader_Verified") != std::string::npos )
    {
        m_appContext.security->PromoteTemporaryKeys();
        m_appContext.security->SetHandshakeVerified( true );
        GlobalUtils::LogToConsole( "Security", "Handshake Verified (Step C)! Sending ACK." );
        m_client->publish( "wols_ca_mqtt/admin/password_ack", "ACK", 1, false );
    }
    else
    {
        GlobalUtils::LogToConsole( "Security", "Step C Failed! Sending NACK." );
        m_client->publish( "wols_ca_mqtt/admin/password_ack", "NACK", 1, false );
    }

    if (isDebug) GlobalUtils::LogToConsole("DEBUG", MSG_DEBUG_END + "StepC_Process_UploaderVerify");
}

// ==============================================================================

void MqttModule::OnMessageArrived( const std::string &topic, const std::string &payload )
{
    if ( topic == "wols_ca_mqtt/admin/request_key" )
    {
        StepA_Broadcast_PublicKey();
        return;
    }

    if ( topic == "wols_ca_mqtt/admin/encrypted_credentials" )
    {
        StepB_Process_Credentials( payload );
        return;
    }

    if ( topic == "wols_ca_mqtt/admin/uploader_verify" )
    {
        StepC_Process_UploaderVerify( payload );
        return;
    }

    if ( !m_appContext.security->GetHandshakeVerified() ) return;

    try
    {
        if ( payload.find( "header" ) != std::string::npos )
        {
            m_appContext.config->UpdateFromPush( payload );
        }
    }
    catch ( ... ) {}
}

bool MqttModule::TestNewCredentials( const std::string &host, const std::string &user, const std::string &pass ) 
{
    try 
    {
        // Wols CA Standard: Synchronous test client to avoid disrupting the main loop
        std::string testUrl = host;
        if ( testUrl.find( "mqtt://" ) == 0 ) testUrl.replace( 0, 7, "tcp://" );
        else if ( testUrl.find( "://" ) == std::string::npos ) testUrl = "tcp://" + testUrl;

        mqtt::client testClient( testUrl, "WolsCA_Test_" + m_instanceId );
        auto opts = mqtt::connect_options_builder().user_name(user).password(pass).connect_timeout(std::chrono::seconds(5)).finalize();
        
        testClient.connect(opts)->wait();
        testClient.disconnect()->wait();
        return true;
    } 
    catch (...) 
    {
        return false;
    }
}

bool MqttModule::UpdateAndReconnect( const std::string &host, const std::string &user, const std::string &pass ) 
{
    m_appContext.config->SetString(ConfigKey::MqttUrl, host);
    m_appContext.config->SetString(ConfigKey::MqttUserId, user);
    m_appContext.config->SetString(ConfigKey::MqttPassword, pass);
    
    // Save to disk and disconnect to force a reconnect loop
    m_appContext.config->SaveMqttConfig(host, user, pass);
    if ( m_client && m_client->is_connected() ) m_client->disconnect()->wait();
    
    return true;
}

void MqttModule::ConnectToBroker( bool bFirst )
{
    std::string url  = m_appContext.config->GetString( ConfigKey::MqttUrl );
    std::string user = m_appContext.config->GetString( ConfigKey::MqttUserId );
    std::string pass = m_appContext.config->GetString( ConfigKey::MqttPassword );

    if ( url.empty() ) { GlobalUtils::LogToConsole( "MQTT", MSG_FATAL_URL ); return; }

    if ( url.find( "mqtt://" ) == 0 ) url.replace( 0, 7, "tcp://" );
    else if ( url.find( "://" ) == std::string::npos ) url = "tcp://" + url;

    m_client = std::make_unique<mqtt::async_client>( url, "