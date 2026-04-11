#include "include/GlobalUtilities.hpp"
#include "include/ApplicationContext.hpp"
#include "include/ConfigManager.hpp"
#include "include/ModuleManager.hpp"
#include "include/MqttModule.hpp"
#include <algorithm>
#include <chrono>
#include <cpr/cpr.h>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h> // Toegevoegd voor SHA256
#include <sstream>
#include <unordered_map>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment( lib, "ws2_32.lib" )
#else
#include <limits.h>
#include <unistd.h>
#endif

namespace GlobalUtils
{

static int s_logModus = 1;

std::string SetLogModus( const int log_mode )
{
    s_logModus = log_mode;
    return "Log modus updated to " + std::to_string( log_mode );
}

// --- Hashing & Mailbox Logic ---

std::string Sha256( const std::string &input )
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX    sha256;
    SHA256_Init( &sha256 );
    SHA256_Update( &sha256, input.c_str(), input.size() );
    SHA256_Final( hash, &sha256 );

    std::stringstream ss;
    // We gebruiken de eerste 8 bytes (16 karakters) voor een compact maar veilig topic [cite: 2026-04-09]
    for ( int i = 0; i < 8; i++ )
    {
        ss << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( hash[i] );
    }
    return ss.str();
}

std::string GetMailboxPath( const std::string &mailboxId, const std::string &subTopic )
{
    // Uniform pad volgens Wols CA standaard: wols_ca_mqtt/mb/[hashed_id]/[hashed_topic] [cite: 2026-04-09]
    return "wols_ca_mqtt/mb/" + Sha256( mailboxId ) + "/" + Sha256( subTopic );
}

// --- Bestaande Functies ---

std::string MinutesToTimestamp( const TimeConversionParams *params )
{
    if ( params == nullptr )
    {
        return "00:00";
    }

    int hours            = params->minutes / 60;
    int remainingMinutes = params->minutes % 60;

    std::ostringstream oss;
    oss << std::setfill( '0' ) << std::setw( 2 ) << hours << ":"
        << std::setfill( '0' ) << std::setw( 2 ) << remainingMinutes;

    return oss.str();
}

std::string MyIsoTimeStampNow()
{
    std::string tz = "Europe/Amsterdam";

    if ( theAppContext && theAppContext->config )
    {
        std::string configTz = theAppContext->config->GetString( ConfigKey::LocalTimeZone );
        if ( !configTz.empty() )
        {
            tz = configTz;
        }
    }

#ifdef _WIN32
    _putenv_s( "TZ", tz.c_str() );
    _tzset();
#else
    setenv( "TZ", tz.c_str(), 1 );
    tzset();
#endif

    std::time_t t = std::time( nullptr );
    std::tm     buf{};
#ifdef _WIN32
    localtime_s( &buf, &t );
#else
    localtime_r( &t, &buf );
#endif

    char ts[32];
    std::strftime( ts, sizeof( ts ), "%Y-%m-%dT%H:%M:%S", &buf );

    char offset[8];
    std::strftime( offset, sizeof( offset ), "%z", &buf );
    std::string off( offset );
    if ( off.length() == 5 )
    {
        off.insert( 3, ":" );
    }

    return std::string( ts ) + off;
}

std::string GetCurrentDate()
{
    std::time_t t = std::time( nullptr );
    std::tm     buf{};
#ifdef _WIN32
    localtime_s( &buf, &t );
#else
    localtime_r( &t, &buf );
#endif

    char ts[16];
    std::strftime( ts, sizeof( ts ), "%Y-%m-%d", &buf );
    return std::string( ts );
}

void LogToConsole( const std::string &moduleName, const std::string &message )
{
    if ( s_logModus == 0 )
    {
        return;
    }
    LogToConsoleNoLock( moduleName, message );
}

void LogToConsoleNoLock( const std::string &moduleName, const std::string &message )
{
    if ( s_logModus == 0 )
    {
        return;
    }

    if ( s_logModus == 2 )
    {
        if ( message.find( "Error" ) == std::string::npos && moduleName != "CRITICAL" )
        {
            return;
        }
    }

    if ( theAppContext && theAppContext->config && theAppContext->config->GetBool( ConfigKey::ConsoleToMqtt ) )
    {
        if ( theAppContext->mqtt && theAppContext->mqtt->IsActive() )
        {
            if ( theAppContext->mqtt->PublishLog( message, moduleName, MyIsoTimeStampNow() ) )
            {
                return;
            }
        }
    }

    std::cout << "[" << MyIsoTimeStampNow() << "][" << moduleName << "] " << message << std::endl;
}

std::string ToLower( const std::string &input )
{
    std::string result = input;
    std::transform( result.begin(), result.end(), result.begin(),
                    []( unsigned char c )
                    { return static_cast<char>( std::tolower( c ) ); } );
    return result;
}

std::string SanitizeTopic( const std::string &input )
{
    std::string result = ToLower( input );

    for ( char &c : result )
    {
        if ( c == '-' || c == ' ' )
        {
            c = '_';
        }
    }
    return result;
}

std::string RemoveSpaces( const std::string &input )
{
    std::string result = input;
    result.erase( std::remove( result.begin(), result.end(), ' ' ), result.end() );
    return result;
}

std::string GetLocationNameFromCoordinates( const std::string &lat, const std::string &lon )
{
    std::string   url      = "https://nominatim.openstreetmap.org/reverse?format=json&lat=" + lat + "&lon=" + lon + "&zoom=10";
    cpr::Response response = cpr::Get( cpr::Url{ url }, cpr::Header{ { "User_Agent", "Wols_CA_HomeAssistant/1.0" } }, cpr::Timeout{ 5000 } );

    if ( response.status_code == 200 )
    {
        try
        {
            auto j = nlohmann::json::parse( response.text );
            if ( j.contains( "address" ) )
            {
                std::string city = "";
                if ( j["address"].contains( "city" ) )
                {
                    city = j["address"]["city"];
                }
                else if ( j["address"].contains( "town" ) )
                {
                    city = j["address"]["town"];
                }
                else if ( j["address"].contains( "village" ) )
                {
                    city = j["address"]["village"];
                }
                else if ( j["address"].contains( "county" ) )
                {
                    city = j["address"]["county"];
                }

                std::string country = j["address"].value( "country", "Unknown" );

                if ( !city.empty() )
                {
                    return city + ", " + country;
                }
                else
                {
                    return country;
                }
            }
        }
        catch ( ... )
        {
            LogToConsole( "GeoLocation", "Error parsing OpenStreetMap JSON." );
        }
    }
    return "Unknown Location";
}

bool GenerateRsaKeyPair( std::string &outPublicKey, std::string &outPrivateKey )
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id( EVP_PKEY_RSA, nullptr );
    if ( !ctx )
    {
        return false;
    }

    if ( EVP_PKEY_keygen_init( ctx ) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits( ctx, 2048 ) <= 0 )
    {
        EVP_PKEY_CTX_free( ctx );
        return false;
    }

    EVP_PKEY *pkey = nullptr;
    if ( EVP_PKEY_keygen( ctx, &pkey ) <= 0 )
    {
        EVP_PKEY_CTX_free( ctx );
        return false;
    }

    BIO *priBio = BIO_new( BIO_s_mem() );
    PEM_write_bio_PrivateKey( priBio, pkey, nullptr, nullptr, 0, nullptr, nullptr );
    size_t priLen = static_cast<size_t>( BIO_pending( priBio ) );
    outPrivateKey.resize( priLen );
    BIO_read( priBio, &outPrivateKey[0], static_cast<int>( priLen ) );
    BIO_free_all( priBio );

    BIO *pubBio = BIO_new( BIO_s_mem() );
    PEM_write_bio_PUBKEY( pubBio, pkey );
    size_t pubLen = static_cast<size_t>( BIO_pending( pubBio ) );
    outPublicKey.resize( pubLen );
    BIO_read( pubBio, &outPublicKey[0], static_cast<int>( pubLen ) );
    BIO_free_all( pubBio );

    EVP_PKEY_free( pkey );
    EVP_PKEY_CTX_free( ctx );
    return true;
}

std::string Base64Decode( const std::string &encoded )
{
    BIO *bio = BIO_new_mem_buf( encoded.data(), static_cast<int>( encoded.size() ) );
    BIO *b64 = BIO_new( BIO_f_base64() );
    bio      = BIO_push( b64, bio );
    BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL );

    std::string decoded( encoded.size(), '\0' );
    int         len = BIO_read( bio, &decoded[0], static_cast<int>( encoded.size() ) );
    BIO_free_all( bio );

    if ( len < 0 )
    {
        throw std::runtime_error( "Base64 decode failed" );
    }
    decoded.resize( len );
    return decoded;
}

std::string RsaPrivateDecrypt( const std::string &privateKeyPem, const std::string &encryptedData )
{
    if ( encryptedData.empty() || privateKeyPem.empty() )
    {
        return "";
    }

    std::string rawEncryptedBytes;
    try
    {
        rawEncryptedBytes = Base64Decode( encryptedData );
    }
    catch ( ... )
    {
        return "";
    }

    BIO      *bio  = BIO_new_mem_buf( privateKeyPem.data(), -1 );
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey( bio, nullptr, nullptr, nullptr );
    BIO_free_all( bio );

    if ( !pkey )
    {
        return "";
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new( pkey, nullptr );
    if ( !ctx )
    {
        EVP_PKEY_free( pkey );
        return "";
    }

    if ( EVP_PKEY_decrypt_init( ctx ) <= 0 ||
         EVP_PKEY_CTX_set_rsa_padding( ctx, RSA_PKCS1_OAEP_PADDING ) <= 0 ||
         EVP_PKEY_CTX_set_rsa_oaep_md( ctx, EVP_sha256() ) <= 0 ||
         EVP_PKEY_CTX_set_rsa_mgf1_md( ctx, EVP_sha256() ) <= 0 )
    {
        EVP_PKEY_CTX_free( ctx );
        EVP_PKEY_free( pkey );
        return "";
    }

    size_t outlen = 0;

    if ( EVP_PKEY_decrypt( ctx, nullptr, &outlen, reinterpret_cast<const unsigned char *>( rawEncryptedBytes.data() ), static_cast<int>( rawEncryptedBytes.size() ) ) <= 0 )
    {
        EVP_PKEY_CTX_free( ctx );
        EVP_PKEY_free( pkey );
        return "";
    }

    std::string decrypted( outlen, '\0' );

    if ( EVP_PKEY_decrypt( ctx, reinterpret_cast<unsigned char *>( &decrypted[0] ), &outlen, reinterpret_cast<const unsigned char *>( rawEncryptedBytes.data() ), static_cast<int>( rawEncryptedBytes.size() ) ) <= 0 )
    {
        EVP_PKEY_CTX_free( ctx );
        EVP_PKEY_free( pkey );
        return "";
    }

    decrypted.resize( outlen );
    EVP_PKEY_CTX_free( ctx );
    EVP_PKEY_free( pkey );
    return decrypted;
}

std::string FetchHostName()
{
    char hostname[256];
    if ( gethostname( hostname, sizeof( hostname ) ) == 0 )
    {
        return std::string( hostname );
    }
    return "UnknownHost";
}

bool IsItTime( const ScheduledTimeParams *params )
{
    if ( !params )
    {
        return false;
    }

    std::time_t t = std::time( nullptr );
    std::tm     nowBuf{};
#ifdef _WIN32
    localtime_s( &nowBuf, &t );
#else
    localtime_r( &t, &nowBuf );
#endif

    return ( nowBuf.tm_hour == params->targetHour && nowBuf.tm_min == params->targetMinute );
}

std::string ExportPublicKeyPem( EVP_PKEY *pkey )
{
    if ( !pkey )
    {
        return "";
    }
    BIO *bio = BIO_new( BIO_s_mem() );
    PEM_write_bio_PUBKEY( bio, pkey );
    size_t      len = static_cast<size_t>( BIO_pending( bio ) );
    std::string pem( len, '\0' );
    BIO_read( bio, &pem[0], static_cast<int>( len ) );
    BIO_free_all( bio );
    return pem;
}

std::string ExportPrivateKeyPem( EVP_PKEY *pkey )
{
    if ( !pkey )
    {
        return "";
    }
    BIO *bio = BIO_new( BIO_s_mem() );
    PEM_write_bio_PrivateKey( bio, pkey, nullptr, nullptr, 0, nullptr, nullptr );
    size_t      len = static_cast<size_t>( BIO_pending( bio ) );
    std::string pem( len, '\0' );
    BIO_read( bio, &pem[0], static_cast<int>( len ) );
    BIO_free_all( bio );
    return pem;
}

} // namespace GlobalUtils