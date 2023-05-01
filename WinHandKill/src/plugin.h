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
#pragma once
#include "pluginmain.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <ShlObj_core.h>

/// <summary>
///		Essas são declarações globais utilizados durante a execução do plugin
/// </summary>
static bool g_run = true; // Utilizado para definir momento de execução dos hooks no processo
static std::string g_client_randoms; //Armazena as chaves do SslHashHandshake, para a thread e contexto.
static std::string g_stages; // Armazena os estágios de expand traffic keys
static std::string g_sufix; // Sufixo de expand traffic keys para serem armazenados em log

/// <summary>
///		Esse enum é responsável a gerenciar cada ID de utilização do menu de iteração de plugins do x64dbg
/// </summary>
enum MenuWinHandKill {

	USE,
	ABOUT

};

/// <summary>
///		Essas são as assinaturas dos procedimentos dos plugins, basicas da sdk do x64dbg
/// </summary>
auto pluginInit(PLUG_INITSTRUCT* initStruct) -> bool;
auto pluginStop() -> void;
auto pluginSetup() -> void;
