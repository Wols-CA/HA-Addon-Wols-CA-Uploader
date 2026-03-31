Groot gelijk !Het is inmiddels ruim na middernacht, hoog tijd om de "creatief met kurk" knutselspullen op te ruimen en de boel veilig op te slaan.

                                                    Hier is het complete,
    opgeschoonde masterplan.Je kunt dit hele blok in één keer kopiëren en opslaan in een tekstbestand(bijv.Wols_Architectuur.md), zodat je morgen direct verder kunt waar we gebleven waren.

                                                                                                                                  Slaap lekker alvast,
    en hier is je code ! 🌙

🚀 De WOLS - CA MQTT Veiligheidsarchitectuur(Master Document) 1. Het Concept(De "Gatekeeper" & Pre - Shared Token) Geen Mosquitto - wachtwoorden over de lijn : We gebruiken een onafhankelijke HandshakeToken in JSON - formaat.

                                                                                                                                                                                                                          Volledig Asynchroon : Geen blokkerende while (true) loops meer,
    waardoor de MQTT Keep - Alive(95 - seconden timeout) in leven blijft.

                            Mosquitto als Firewall : De C++ service abonneert zich alleen op handshake
        - topics.Pas als het wachtwoord(de token) klopt,
    worden de operationele spotify / #topics geopend.

                                     2. De Configuratie(Eenmalig instellen)
                                         In Home Assistant(/ config / secrets.yaml) :

                                                                                      YAML handshake_token : "WolsCaVeilig2026" In de C++ Configuratie(GlobalVar of je JSON config) : Zorg dat de service exact dezelfde string kent,
bijvoorbeeld via ConfigKey::HandshakeToken.

    3. Python Code(De Uploader)
        In public_key_handler.py(of waar je de payload verstuurt) : Maak een schone JSON
    - string en versleutel deze in zijn geheel.Geen strings knippen of plakken !

      Python
      import json
      import logging
#(Andere imports zoals RSA encryptie functies)

      def send_encrypted_handshake(client, public_key_pem) :
# 1. Haal de token op uit secrets.yaml
                                                             token = get_secret("handshake_token") if not token : logging.error("❌ 'handshake_token' niet gevonden in secrets.yaml!") return

# 2. Bouw het schone JSON object
                                                                                                                  payload_data = {
    "handshake_token" : token
}

# 3. Maak er een string van : {"handshake_token" : "WolsCaVeilig2026" }
json_string = json.dumps(payload_data)

# 4. Versleutel de hele string met RSA
                  encrypted_bytes = encrypt_with_public_key(json_string, public_key_pem)

# 5. Publiceer naar C ++
                                        client.publish("wols-ca/admin/encrypted_password", encrypted_bytes, qos = 1, retain = False)
                                            logging.info("🔒 Versleutelde Handshake Token verstuurd via JSON!") 4. C++ Code(De Gatekeeper Service)
                                                A.Non
                                    - blocking MQTT Connectie(met detached thread) Fikst de 95 - seconden Keep - Alive disconnect bug.

                                                                                                                 C++ void MqttModule::ConnectToBroker(bool bFirst)
{
    // ... [Je bestaande setup & logging code] ...

    if (bFirst)
    {
        // ── Detached Thread Callback ──
        GlobalVar::GetMqttClient()->set_message_callback(
            [this](mqtt::const_message_ptr msg)
            {
                if (msg)
                {
                    std::string topic = msg->get_topic();
                    std::string payload = msg->to_string();

                    // Voer OnMessageArrived uit op de achtergrond, bevrijd de MQTT ping thread!
                    std::thread([this, topic, payload]()
                                { this->OnMessageArrived(topic, payload); })
                        .detach();
                }
            });

        // ... [Je connect options setup] ...
    }

    // ── Verbinden ──
    if (!GlobalVar::GetMqttClient()->is_connected())
    {
        try
        {
            GlobalVar::GetMqttClient()->connect(m_connectOptions)->wait();

            // 🚀 Abonneer in eerste instantie ALLEEN op de veilige topics
            SubscribeToKeyTopics();

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        catch (mqtt::exception &e)
        { /* Error handling */
        }
    }
}
B.De Gatekeeper Functies(Mosquitto als Firewall)
    C++ void MqttModule::SubscribeToKeyTopics()
{
    if (GlobalVar::GetMqttClient() && GlobalVar::GetMqttClient()->is_connected())
    {
        // 1. Sluit de operationele poorten (Lockdown)
        std::string filter = m_rootTopic + "#";
        GlobalVar::GetMqttClient()->unsubscribe(filter);

        // 2. Open alleen de voordeur
        GlobalVar::GetMqttClient()->subscribe("wols-ca/admin/encrypted_password", 1);
        GlobalVar::GetMqttClient()->subscribe("wols-ca/admin/request_key", 1);
        GlobalVar::GetMqttClient()->subscribe("wols-ca/uploader/version", 1);
        GlobalVar::GetMqttClient()->subscribe("wols-ca/uploader/required_version", 1);

        GlobalUtils::LogToConsole(GetModuleName(), "🔒 GATEKEEPER ACTIEF: Operationele topics geblokkeerd.");
    }
}

void MqttModule::SubscribeToOperationalTopics()
{
    if (GlobalVar::GetMqttClient() && GlobalVar::GetMqttClient()->is_connected())
    {
        // Gooi de hele app open nadat de token klopt!
        std::string filter = m_rootTopic + "#";
        GlobalVar::GetMqttClient()->subscribe(filter, 1);

        GlobalUtils::LogToConsole(GetModuleName(), "🔓 HANDSHAKE SUCCES: Geabonneerd op operationele Spotify topics.");
    }
}
C.Event - Driven Opstarten(Geen While - Loops !)
              C++ void MqttModule::VerificationStepOnConnect()
{
    theGlobalVar->m_verificationInProgress = true;
    SetHandshakeVerified(false);

    PublishMqttSettings();
    SubscribeToKeyTopics(); // Zorg dat we op slot starten

    // GEEN `while(true)` LOOP MEER!
    // Genereer de key (met retain=false in GlobalVar!) en wacht op de callback.
    GlobalUtils::LogToConsole(GetModuleName(), "Initiating Handshake sequence...");
    theGlobalVar->GenerateKeyPair();
}
D.De OnMessage Handler(De Uitsmijter)
    C++ void MqttModule::OnMessage(const std::string &topic, const std::string &payload)
{
    size_t lastSlash = topic.find_last_of('/');
    std::string key = (lastSlash == std::string::npos) ? topic : topic.substr(lastSlash + 1);

    // ─── ADMIN COMMANDO: LOCK ───
    if (key == "command" && payload == "LOCK")
    {
        GlobalUtils::LogToConsole(GetModuleName(), "🚨 LOCK commando ontvangen! Poorten worden gesloten.");
        SetHandshakeVerified(false);
        SubscribeToKeyTopics();
        return;
    }

    // ─── RE-KEY REQUEST ───
    if (key == "request_key" && payload == "STARTUP_SYNC")
    {
        GlobalUtils::LogToConsole(GetModuleName(), "Python uploader vraagt om nieuwe key. Locking gates...");
        SetHandshakeVerified(false);
        SubscribeToKeyTopics();
        theGlobalVar->GenerateKeyPair(); // Publiceer nieuwe public key
        return;
    }

    // ─── GATEKEEPER CHECK ───
    if (!IsHandshakeVerified())
    {
        if (key == "encrypted_password")
        {
            GlobalUtils::LogToConsole(GetModuleName(), "Gatekeeper: Received encrypted payload. Verifying...");

            bool isValid = theGlobalVar->HandleEncryptedPassword(payload);
            SetHandshakeVerified(isValid);

            if (isValid)
            {
                theGlobalVar->m_verificationInProgress = false;
                SubscribeToOperationalTopics(); // 🔓 Ontgrendel de app!
            }
        }
        else if (key == "version")
        { /* Version logica */
        }

        // Return ALTIJD zolang de handshake niet is voltooid.
        return;
    }

    // ─── OPERATIONELE LOGICA ───
    // Hier kom je alleen als SubscribeToOperationalTopics is aangeroepen.
    try
    {
        auto j = nlohmann::json::parse(payload);
        // ... [Je bestaande Spotify/Instellingen config logica] ...
    }
    catch (...)
    {
    }
}
E.JSON Decryptie(Schoon en Massief Staal)
    C++ bool GlobalVar::HandleEncryptedPassword(const std::string &encryptedPayload)
{
    std::string decryptedText = DecryptRsa(encryptedPayload);

    if (decryptedText.empty())
    {
        GlobalUtils::LogToConsole("Gatekeeper", "❌ Decryption failed!");
        return false;
    }

    try
    {
        // Parse de JSON string die van Python komt
        auto j = nlohmann::json::parse(decryptedText);

        std::string receivedToken = j.value("handshake_token", "");
        std::string expectedToken = GetString(ConfigKey::HandshakeToken); // Of hardcoded

        if (!receivedToken.empty() && receivedToken == expectedToken)
        {
            GlobalUtils::LogToConsole("Gatekeeper", "✅ JSON Token Verified!");
            return true;
        }
        else
        {
            GlobalUtils::LogToConsole("Gatekeeper", "❌ Invalid Handshake Token!");
            return false;
        }
    }
    catch (...)
    {
        GlobalUtils::LogToConsole("Gatekeeper", "❌ Fout tijdens het parsen van de JSON payload.");
        return false;
    }
}