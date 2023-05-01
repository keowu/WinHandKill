/*
 _   __ _____ _____  _    _ _   _
| | / /|  ___|  _  || |  | | | | |
| |/ / | |__ | | | || |  | | | | |
|    \ |  __|| | | || |/\| | | | |
| |\  \| |___\ \_/ /\  /\  / |_| |
\_| \_/\____/ \___/  \/  \/ \___/
                            2023
Copyright (c) Fluxuss Cyber Tech Desenvolvimento de Software, SLU (FLUXUSS)
Copyright (c) Fluxuss Software Security, LLC
*/
#include "plugin.h"

/// <summary>
///     Este procedimento é responsável por gravar argumentos de std::string
///     em um arquivo de texto, sempre adionando o novo conteúdo ao final.
/// </summary>
/// <param name="arg">Argumento a ser escrito no arquivo de logs</param>
/// <returns>Não possui retorno explicito</returns>
auto writeLogKeys(std::string arg) -> void {

    std::ofstream outfile;

    outfile.open("c:\\lsassExtractedKeys.txt", std::ios_base::app);

    outfile << arg << "\n";

    outfile.close();

}

/// <summary>
///     Este procedimento é responsável por converter um bloco de memória em um std::string.
///     De maneira direta um ponteiro é recebido, cada byte é lido em um stream com um tamanho máximo determinado.
///     Esses bytes são armazenados como um char* válido em um std::string, considerando sobre 2 bytes, e de maneira que os
///     bytes fiquem dispostos de maneira minúscula.
/// </summary>
/// <param name="buff">Ponteiro para a região onde os bytes estão armazenados</param>
/// <param name="len">Tamanho dos bytes a serem convertidos</param>
/// <param name="out">String de referência de saída onde os dados serão armazenados</param>
/// <returns>Não possuí um retorno explicito</returns>
auto memoryToString(void* const buff, const size_t len, std::string& out) -> void {

    auto* byteData = reinterpret_cast<unsigned char*>(buff);

    std::stringstream hexStringStream;

    hexStringStream << std::hex << std::setfill('0');

    for (size_t index = 0; index < len; ++index) hexStringStream << std::nouppercase << std::setw(2) << static_cast<int>(byteData[index]) << "";

    out = hexStringStream.str().append("\0");

}

/// <summary>
///     Esta thread é responsável por parar a execução do WinHandKill.
///     Para isso utiliza-se chamadas para a winapi GetAsyncKeyState combinando CTRL + 1
///     Desta forma definindo a flag global de execução para false, encerrando a execução dos hooks de execução no x64dbg
/// </summary>
/// <param name="args">Argumentos opcionais de callback da windows api CreteThread</param>
/// <returns>Não possuí retorno explicito</returns>
auto WINAPI thCheckUserNeedStopSafety(PVOID args) -> DWORD {

    while (g_run) {

        if (GetAsyncKeyState(VK_CONTROL) & 0x8000 && GetAsyncKeyState(0x31) & 0x8000) {

            Script::Gui::Message("Ok, WinHandKill has been paused, now please check if the x64dbg breakpoint section has any assets, and if so, remove them for safety, and ensure that the lsass.exe process does not have any int3 breakpoints defined. because if you are, you will definitely have UAC activated, causing your operating system to crash completely in 1 minute. also remember to unfasten (UNDER NO WAY END THE PROCESS), to get your keys go to c:\\lsassExtractedKeys.txt");

            g_run = false;

            break;
        }

    }

    return WN_SUCCESS;
}

/// <summary>
///     Esta thread é responsável por definir os hooks necessários para obter as chaves pelas chamadas efetuadas pelo sistema operacional
///     para o processo protegido lsass.exe. dessa forma definindo os deslocamentos de início e fim das chamadas quando necessário e lendo os dados
///     conforme são dispostos em memória, manipulando e avaliando chamadas para os endereços necessários para execução das rotinas necessárias para extração das chaves TLS
///     com base no padrão e característica de chamadas do sistema operacional.
/// </summary>
/// <param name="args">Argumentos opcionais de callback da windows api CreteThread</param>
/// <returns>Não possuí retorno explicito</returns>
auto WINAPI thWinHandWorking(PVOID args) -> DWORD {

    auto pSslHashHandShake = Script::Module::BaseFromName("ncrypt.dll") + 0x10F0; //This offset is the begin of function

    _plugin_logprintf("\nBASE: %0.8X\n", pSslHashHandShake);

    Script::Debug::SetBreakpoint(pSslHashHandShake);

    auto pSslGenerateMasterKey = Script::Module::BaseFromName("ncrypt.dll") + 0x1E50; //This offset is the begin of function

    Script::Debug::SetBreakpoint(pSslGenerateMasterKey);

    auto pSslImportMasterKey = Script::Module::BaseFromName("ncrypt.dll") + 0xC2B0; //This offset is the begin of function 

    Script::Debug::SetBreakpoint(pSslImportMasterKey);

    auto SslGenerateSessionKeys = Script::Module::BaseFromName("ncrypt.dll") + 0x12A0; //This offset is the begin of function

    Script::Debug::SetBreakpoint(SslGenerateSessionKeys);

    auto SslExpandTrafficKeys = Script::Module::BaseFromName("ncrypt.dll") + 0xB3B0; //This offset is the begin of function

    Script::Debug::SetBreakpoint(SslExpandTrafficKeys);

    auto SslExpandExporterMasterKey = Script::Module::BaseFromName("ncrypt.dll") + 0xB1F0; //This offset is the begin of function
    Script::Debug::SetBreakpoint(SslExpandExporterMasterKey);

    while (g_run) {

        auto actual_eip = Script::Register::GetRIP();

        /*
            Isso funciona para TLS 1.3 e TLS 1.2
            A primeira mensagem é o hello então o msg_type vai ser 1 e a versão vai ser 0x0303
            A versão 0x0303 funciona para TLS 1.2 e TLS 1.3 de acordo com a RFC 7627
        */
        if (actual_eip == pSslHashHandShake) {

            auto buffer = DbgEval("arg.get(2)");
            auto length = DbgEval("arg.get(3)");

            //READ MSG_TYPE and VERSION
            UINT8 msg_type = 0; UINT16 version_tls = 0;
            
            auto memAddyBeginVersion = buffer + 4;

            Script::Memory::Read(memAddyBeginVersion, &version_tls, sizeof(UINT16), NULL);

            Script::Memory::Read(buffer, &msg_type, sizeof(UINT8), NULL);

            if (msg_type == 1 && version_tls == 0x0303) {

                //READ CLIENTE RANDOM KEY
                auto memAddyBegin = buffer + 6;
                auto client_random_bytes = new unsigned char[32];
                Script::Memory::Read(memAddyBegin, client_random_bytes, 32, NULL); // Lê 32 bytes da chave AES do random
                
                _plugin_logprintf("\nBuffer: %0.8X, Lenght: %0.4X, Version: %X\n", buffer, length, version_tls);

                _plugin_logprintf("\nBEGIN CLIENTE RANDOM:\n");

                std::string outBytes("");

                memoryToString(client_random_bytes, 32, outBytes);

                g_client_randoms = std::string(outBytes);

                _plugin_logprintf("\n%s\n", outBytes.c_str());
            }
            //else _plugin_logprintf("\nSorry this are not correct msg_type: %X and Version: %X\n", msg_type, version_tls);

            Script::Debug::Run();
        }

        /*
            Isso funciona para TLS 1.2
        */
        if (actual_eip == pSslGenerateMasterKey) {

            auto phMasterkey = DbgEval("arg.get(3)");
            auto hSslProvider = DbgEval("arg.get(0)");
            auto pParametersList = DbgEval("arg.get(6)");
            
            /*
            
            Parsing random from _NCryptBufferDesc, _NcryptBuffer

            */
            auto pBuffercount = pParametersList + 4;
            UINT32 bufferCount = 0;
            Script::Memory::Read(pBuffercount, &bufferCount, sizeof(UINT32), NULL);
            auto pBuffers = pParametersList + 8;
            /*
                Preciso recuperar o valor do ponteiro armazenado
                vamos considerar um ponteiro da arquitetura X64
                vamos ler oito bytes, acessar esses oito bytes e retornar
            */
            duint pBuffer = 0;
            Script::Memory::Read(pBuffers, &pBuffer, sizeof(duint), NULL);

            std::string l_client_random("");

            for (auto i = 0; i < bufferCount; i++) {

                auto buf = (pBuffer + (16 * i));

                UINT32 buf_size = 0;
                Script::Memory::Read(buf, &buf_size, sizeof(UINT32), NULL);
                
                UINT32 buf_type = 0;
                Script::Memory::Read(buf + 4, &buf_type, sizeof(UINT32), NULL);

                duint buf_buf_p = 0;
                Script::Memory::Read(buf + 8, &buf_buf_p, sizeof(duint), NULL);

                auto buff_buff = new unsigned char[buf_size];
                Script::Memory::Read(buf_buf_p, buff_buff, buf_size, NULL);

                if (buf_type == 20) { //NCRYPT_BUFFER_SSL_CLIENT_RANDOM

                    memoryToString(buff_buff, buf_size, l_client_random);

                    break;
                }

            }

            auto client_random = std::string("");

            if (l_client_random.empty()) client_random = g_client_randoms;
            else client_random = l_client_random;

            if (client_random.empty()) client_random = "???";

            //SET BREAKPOINT AT END
            auto pSslGenerateMasterKeyEnd = Script::Module::BaseFromName("ncrypt.dll") + 0x2030; //This offset is for end of SslGenerateMasterKey

            Script::Debug::SetBreakpoint(pSslGenerateMasterKeyEnd);

            Script::Debug::Run();

            duint pPhMasterkey = 0;
            Script::Memory::Read(phMasterkey, &pPhMasterkey, sizeof(duint), NULL);

            duint pSsl15 = 0;
            Script::Memory::Read(pPhMasterkey + 0x10, &pSsl15, sizeof(duint), NULL);

            auto master_key = new unsigned char[48];
            Script::Memory::Read(pSsl15 + 28, master_key, 48, NULL);

            std::string l_master_key("");

            memoryToString(master_key, 48, l_master_key);

            writeLogKeys("CLIENT_RANDOM " + client_random + " " + l_master_key);

            Script::Debug::DeleteBreakpoint(pSslGenerateMasterKeyEnd);

            Script::Debug::Run();
        }

        /*
            This is for TLS 1.2
        */
        if (actual_eip == pSslImportMasterKey) {

            auto phMasterkey = DbgEval("arg.get(2)");
            auto pParameterList = DbgEval("arg.get(5)");

            /*

            Parsing random from _NCryptBufferDesc, _NcryptBuffer

            */
            auto pBuffercount = pParameterList + 4;
            UINT32 bufferCount = 0;
            Script::Memory::Read(pBuffercount, &bufferCount, sizeof(UINT32), NULL);
            auto pBuffers = pParameterList + 8;

            /*
               Preciso recuperar o valor do ponteiro armazenado
               vamos considerar um ponteiro da arquitetura X64
               vamos ler oito bytes, acessar esses oito bytes e retornar
           */
            duint pBuffer = 0;
            Script::Memory::Read(pBuffers, &pBuffer, sizeof(duint), NULL);

            std::string l_client_random("");

            for (auto i = 0; i < bufferCount; i++) {

                auto buf = (pBuffer + (16 * i));

                UINT32 buf_size = 0;
                Script::Memory::Read(buf, &buf_size, sizeof(UINT32), NULL);

                UINT32 buf_type = 0;
                Script::Memory::Read(buf + 4, &buf_type, sizeof(UINT32), NULL);

                duint buf_buf_p = 0;
                Script::Memory::Read(buf + 8, &buf_buf_p, sizeof(duint), NULL);

                auto buff_buff = new unsigned char[buf_size];
                Script::Memory::Read(buf_buf_p, buff_buff, buf_size, NULL);

                if (buf_type == 20) { //NCRYPT_BUFFER_SSL_CLIENT_RANDOM

                    memoryToString(buff_buff, buf_size, l_client_random);

                    break;
                }

            }

            auto client_random = std::string("");

            if (l_client_random.empty()) client_random = g_client_randoms;
            else client_random = l_client_random;

            if (client_random.empty()) client_random = "???";

            //SET BREAKPOINT AT END
            auto pSslImportMasterKeyEnd = Script::Module::BaseFromName("ncrypt.dll") + 0x3BBF; //This offset is for end of SslGenerateMasterKey

            Script::Debug::SetBreakpoint(pSslImportMasterKeyEnd);

            Script::Debug::Run();

            duint pPhMasterkey = 0;
            Script::Memory::Read(phMasterkey, &pPhMasterkey, sizeof(duint), NULL);

            duint pSsl15 = 0;
            Script::Memory::Read(pPhMasterkey + 0x10, &pSsl15, sizeof(duint), NULL);

            auto master_key = new unsigned char[48];
            Script::Memory::Read(pSsl15 + 28, master_key, 48, NULL);

            std::string l_master_key("");

            memoryToString(master_key, 48, l_master_key);

            writeLogKeys("CLIENT_RANDOM " + client_random + " " + l_master_key);

            Script::Debug::DeleteBreakpoint(pSslImportMasterKeyEnd);

            Script::Debug::Run();
        }

        /*
            TLS 1.2 storage for client and server for normal or resumed session (RFC 7627)
        */
        if (actual_eip == SslGenerateSessionKeys) {

            auto hMasterKey = DbgEval("arg.get(1)");
            auto hSslProvider = DbgEval("arg.get(0)");
            auto pParameterList = DbgEval("arg.get(4)");

            /*

            Parsing random from _NCryptBufferDesc, _NcryptBuffer

            */
            auto pBuffercount = pParameterList + 4;
            UINT32 bufferCount = 0;
            Script::Memory::Read(pBuffercount, &bufferCount, sizeof(UINT32), NULL);
            auto pBuffers = pParameterList + 8;

            /*
              Preciso recuperar o valor do ponteiro armazenado
              vamos considerar um ponteiro da arquitetura X64
              vamos ler oito bytes, acessar esses oito bytes e retornar
            */
            duint pBuffer = 0;
            Script::Memory::Read(pBuffers, &pBuffer, sizeof(duint), NULL);

            std::string l_client_random("");

            for (auto i = 0; i < bufferCount; i++) {

                auto buf = (pBuffer + (16 * i));

                UINT32 buf_size = 0;
                Script::Memory::Read(buf, &buf_size, sizeof(UINT32), NULL);

                UINT32 buf_type = 0;
                Script::Memory::Read(buf + 4, &buf_type, sizeof(UINT32), NULL);

                duint buf_buf_p = 0;
                Script::Memory::Read(buf + 8, &buf_buf_p, sizeof(duint), NULL);

                auto buff_buff = new unsigned char[buf_size];
                Script::Memory::Read(buf_buf_p, buff_buff, buf_size, NULL);

                if (buf_type == 20) { //NCRYPT_BUFFER_SSL_CLIENT_RANDOM

                    memoryToString(buff_buff, buf_size, l_client_random);

                    break;
                }

            }

            auto client_random = std::string("");

            if (l_client_random.empty()) client_random = g_client_randoms;
            else client_random = l_client_random;

            if (client_random.empty()) client_random = "???";

            /*
                Geting master key
            */
                         //hMasterKey aka NcryptSslKey
            auto pSs15 = hMasterKey + 0x10;
            duint prSs15 = 0;
            Script::Memory::Read(pSs15, &prSs15, sizeof(duint), NULL);

            auto masterKey = new unsigned char[48];
            Script::Memory::Read(prSs15 + 28, masterKey, 48, NULL);

            std::string l_master_key("");

            memoryToString(masterKey, 48, l_master_key);

            writeLogKeys("CLIENT_RANDOM " + client_random + " " + l_master_key);

            Script::Debug::Run();
        }

        /*
            TLS 1.3
        */
        if (actual_eip == SslExpandTrafficKeys) {

            auto retKey1 = DbgEval("arg.get(3)");
            auto retKey2 = DbgEval("arg.get(4)");

            auto clientrandom = g_client_randoms;

            if (clientrandom.empty()) clientrandom = "???";

            if (!g_stages.empty()) {
                g_stages = "";
                g_sufix = "TRAFFIC_SECRET_0";
            }
            else {
                g_stages = "handshake";
                g_sufix = "HANDSHAKE_TRAFFIC_SECRET";
            }

            //Set breakpoint at end of function
            auto pSslExpandTrafficKeysEnd = Script::Module::BaseFromName("ncrypt.dll") + 0x3BBF;

            Script::Debug::SetBreakpoint(pSslExpandTrafficKeysEnd);

            Script::Debug::Run();

            /*
                Parse key1 from BDDD
            */
            duint pRetKey1 = 0;
            Script::Memory::Read(retKey1, &pRetKey1, sizeof(duint), NULL); // Get pointer for BDDD Struct

            duint str31SS = 0;
            Script::Memory::Read(pRetKey1 + 0x10, &str31SS, sizeof(duint), NULL);

            duint strRUUU = 0;
            Script::Memory::Read(str31SS + 0x20, &strRUUU, sizeof(duint), NULL);

            duint strYKSM = 0;
            Script::Memory::Read(strRUUU + 0x10, &strYKSM, sizeof(duint), NULL);

            duint pSecretKey = 0;
            Script::Memory::Read(strYKSM + 0x18, &pSecretKey, sizeof(duint), NULL);

            UINT32 szSecret = 0;
            Script::Memory::Read(strYKSM + 0x10, &szSecret, sizeof(UINT32), NULL);

            auto ucSecretKeyBytes = new unsigned char[szSecret];
            Script::Memory::Read(pSecretKey, ucSecretKeyBytes, szSecret, NULL);

            std::string strKey1;

            memoryToString(ucSecretKeyBytes, szSecret, strKey1);

            /*
                Parse key2 from BDDD
            */
            duint pRetKey2 = 0;
            Script::Memory::Read(retKey2, &pRetKey2, sizeof(duint), NULL); // Get pointer for BDDD Struct

            str31SS = 0;
            Script::Memory::Read(pRetKey2 + 0x10, &str31SS, sizeof(duint), NULL);

            strRUUU = 0;
            Script::Memory::Read(str31SS + 0x20, &strRUUU, sizeof(duint), NULL);

            strYKSM = 0;
            Script::Memory::Read(strRUUU + 0x10, &strYKSM, sizeof(duint), NULL);

            pSecretKey = 0;
            Script::Memory::Read(strYKSM + 0x18, &pSecretKey, sizeof(duint), NULL);

            szSecret = 0;
            Script::Memory::Read(strYKSM + 0x10, &szSecret, sizeof(UINT32), NULL);

            ucSecretKeyBytes = new unsigned char[szSecret];
            Script::Memory::Read(pSecretKey, ucSecretKeyBytes, szSecret, NULL);

            std::string strKey2;

            memoryToString(ucSecretKeyBytes, szSecret, strKey1);

            writeLogKeys("CLIENT_" + g_sufix + " " + clientrandom + " " + strKey1);
            writeLogKeys("SERVER_" + g_sufix + " " + clientrandom + " " + strKey2);

            Script::Debug::DeleteBreakpoint(pSslExpandTrafficKeysEnd);

            Script::Debug::Run();
        }

        if (actual_eip == SslExpandExporterMasterKey) {

            auto retkey = DbgEval("arg.get(3)");

            auto clientrandom = g_client_randoms;
            if (clientrandom.empty()) clientrandom = "???";

            //Set brakpoint at end of function
            auto pSslExpandExporterMasterKeyEnd = Script::Module::BaseFromName("ncrypt.dll") + 0x3BBF;

            Script::Debug::SetBreakpoint(pSslExpandExporterMasterKeyEnd);

            Script::Debug::Run();

            duint pRetKey = 0;
            Script::Memory::Read(retkey, &pRetKey, sizeof(duint), NULL);

            //pRetKey + 0x10 and need to take a reference for another pointer struct
            duint pRetRetKey = 0;
            Script::Memory::Read(pRetKey + 0x10, &pRetRetKey, sizeof(duint), NULL);

            //pRetRetKey + 0x20 and need to take more one reference for another pointer struct
            duint pRetRetRetKey = 0;
            Script::Memory::Read(pRetRetKey + 0x20, &pRetRetRetKey, sizeof(duint), NULL);

            //pRetRetRetKey + 0x10 and need to take more one reference for another pointer struct
            duint pRetRetRetRetKey = 0;
            Script::Memory::Read(pRetRetRetKey + 0x10, &pRetRetRetRetKey, sizeof(duint), NULL);

            //pRetRetRetRetKey + 0x18 and need to take more one reference for another pointer struct
            duint pRetRetRetRetRetKey = 0;
            Script::Memory::Read(pRetRetRetRetKey + 0x18, &pRetRetRetRetRetKey, sizeof(duint), NULL);

            auto tlskey = new unsigned char[48];
            Script::Memory::Read(pRetRetRetRetRetKey, tlskey, 48, NULL);
            
            std::string strTlsKey;
            memoryToString(tlskey, 48, strTlsKey);

            writeLogKeys("EXPORTER_SECRET " + clientrandom + " " + strTlsKey);

            Script::Debug::DeleteBreakpoint(pSslExpandExporterMasterKeyEnd);

            Script::Debug::Run();
        }

    }

    Script::Debug::DeleteBreakpoint(pSslHashHandShake);

    Script::Debug::DeleteBreakpoint(pSslGenerateMasterKey);

    Script::Debug::DeleteBreakpoint(pSslImportMasterKey);

    Script::Debug::DeleteBreakpoint(SslGenerateSessionKeys);

    Script::Debug::DeleteBreakpoint(SslExpandTrafficKeys);

    Script::Debug::DeleteBreakpoint(SslExpandExporterMasterKey);

    Script::Debug::Run();

    return WN_SUCCESS;
}

/// <summary>
///     Este procedimento é utilizado para definir as threads necessárias para execução do plugin.
///     Além disso efetua verificações para ter certeza de que o plugin esta em execução em um ambiente correto.
/// </summary>
/// <param name="argc">Argumentos de linha de comando do console do x64dbg</param>
/// <param name="argv">Quantidade de argumentos de linha de comando do console do x64dbg</param>
/// <returns>retorna um boolean, sendo true sucesso para a execução e false para impedir a execução</returns>
static auto setUpWinHandKill(int argc, char* argv[]) -> bool {

    char* chModuleName = new char[MAX_MODULE_SIZE];

    Script::Module::GetMainModuleName(chModuleName);

    if (!IsUserAnAdmin() || std::string(chModuleName).find("lsass.exe") == std::string::npos) {

        Script::Gui::Message("This plugin requires that x64dbg has administrator permissions, and the target process must be lsass.exe.\nWe need to grant the SeDebugPrivilege permission before continuing.");

        return false;
    }

    Script::Gui::Message("Attention, WinHandKill is started, from now on I recommend that you do not manipulate x64dbg in any way, even for security reasons.\nleave the whole process to me, and after collecting your keys, press CTRL + 1.\nif for some reason you want to cancel, also press CTRL + 1.\nand remember that if you close the procedure without using this shortcut, the UAC will definitely be triggered.");

    g_run = true;

    DWORD hTid;

    CreateThread(
        NULL,
        NULL,
        thWinHandWorking,
        NULL,
        NULL,
        &hTid
    );

    _plugin_logprintf("\nBegin thWinHandWorking TID: %X\n", hTid);

    CreateThread(
        NULL,
        NULL,
        thCheckUserNeedStopSafety,
        NULL,
        NULL,
        &hTid
    );    

    _plugin_logprintf("\nBegin thCheckUserNeedStopSafety TID: %X\n", hTid);

    return true;
}

/// <summary>
///     Este procedimento é responsável por definir um comando executável no comando do x64dbg
/// </summary>
/// <param name="initStruct">Struct de inicialização do x64dbg</param>
/// <returns>Retorna true se o procedimento for um sucesso, e false caso algum erro ocorra</returns>
auto pluginInit(PLUG_INITSTRUCT* initStruct) -> bool {

    if (!_plugin_registercommand(pluginHandle, "WinHandKill", setUpWinHandKill, false)) {

        _plugin_logputs("Sorry WinHandKill cannot be loaded correctly.");

        return false;
    }

    return true;
}

/// <summary>
///     Este procedimento é responsável por gerenciar os callbacks do menu de interação de plugins do x64dbg
/// </summary>
/// <param name="cbType">x64dbg callback cbType</param>
/// <param name="info">x64dbg callback info</param>
/// <returns>Não possuí retorno explicito</returns>
PLUG_EXPORT auto CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info) -> void {

    switch (info->hEntry) {

        case MenuWinHandKill::USE:
            Script::Gui::Message("To use it, you need to go to the logs screen, and type \"WinHandKill\".\nOnce started I don't recommend that you modify or change anything in the lsass.exe debug process, leave everything to me. \nif at any time you want to stop the execution use the shortcut CTRL + 1.\nThis plugin has numerous mechanisms to ensure that you can extract the TLS security keys without any problem (no 1 minute UAC for restart) so just run and open your network logging tools to start capturing.");
            break;

        case MenuWinHandKill::ABOUT:
            Script::Gui::Message("This plugin was developed by Keowu(www.github.com/keowu)\nIf you would like to contribute feel free.\nDonate to the x64dbg project(it's Free and Awelsome).");
            break;

        default:
            break;

    }

}

/// <summary>
///     Este procedimento é utilizado ao descarregar o plugin, sua função é desregistrar o comando WinHandKill do console do x64dbg
/// </summary>
/// <returns>Não possuí retorno explicito</returns>
auto pluginStop() -> void {

    _plugin_unregistercommand(pluginHandle, "WinHandKill");

}

/// <summary>
///     Este procedimento é utilizado para definir entradas no menu do x64dbg para o plugin
/// </summary>
/// <returns>Não possuí retorno explicito</returns>
auto pluginSetup() -> void {

    _plugin_menuaddentry(hMenu, MenuWinHandKill::USE, "How to use");
    _plugin_menuaddentry(hMenu, MenuWinHandKill::ABOUT, "About WinHandKill");

}
