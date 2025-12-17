# Check Services

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows" alt="Windows"/>
  <img src="https://img.shields.io/badge/Language-C++-00599C?style=for-the-badge&logo=cplusplus" alt="C++"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT"/>
</p>

```
   _____ _               _      _____                 _               
  / ____| |             | |    / ____|               (_)              
 | |    | |__   ___  ___| | __| (___   ___ _ ____   ___  ___ ___  ___ 
 | |    | '_ \ / _ \/ __| |/ / \___ \ / _ \ '__\ \ / / |/ __/ _ \/ __|
 | |____| | | |  __/ (__|   <  ____) |  __/ |   \ V /| | (_|  __/\__ \
  \_____|_| |_|\___|\___|_|\_\|_____/ \___|_|    \_/ |_|\___\___||___/
```

Ferramenta de monitoramento em tempo real para detectar tentativas de desabilitação de serviços críticos do Windows.

---

## ⚠️ Aviso Importante

> **Esta ferramenta deve ser executada APENAS durante a call com o SS/Analista.**
> 
> Inicie o programa antes da análise começar e mantenha-o rodando durante toda a sessão.

---

## 📋 Serviços Monitorados

| Serviço | Descrição |
|---------|-----------|
| `PcaSvc` | Program Compatibility Assistant |
| `PlugPlay` | Plug and Play |
| `DPS` | Diagnostic Policy Service |
| `DiagTrack` | Connected User Experiences and Telemetry |
| `SysMain` | Superfetch |
| `Sysmon` | System Monitor (Sysinternals) |
| `EventLog` | Windows Event Log |

---

## 🚀 Como Usar

### 1. Baixe a Release
Acesse a aba [Releases](../../releases) e baixe o `CheckServices.exe` mais recente.

### 2. Execute como Administrador
```
Clique direito no .exe → Executar como administrador
```

### 3. Mantenha Aberto Durante a Call
O programa irá monitorar e alertar qualquer tentativa de parar/desabilitar os serviços.

---

## 🖥️ Output

```
   _____ _               _      _____                 _               
  / ____| |             | |    / ____|               (_)              
 | |    | |__   ___  ___| | __| (___   ___ _ ____   ___  ___ ___  ___ 
 | |    | '_ \ / _ \/ __| |/ / \___ \ / _ \ '__\ \ / / |/ __/ _ \/ __|
 | |____| | | |  __/ (__|   <  ____) |  __/ |   \ V /| | (_|  __/\__ \
  \_____|_| |_|\___|\___|_|\_\|_____/ \___|_|    \_/ |_|\___\___||___/

                        [ v2.0 - Service Monitor ]

  [OK] Executando como Administrador
  [*] Log: check_services.log

  [+] Servicos monitorados:
  +-----------------------+-------------+
  | Servico               | Estado      |
  +-----------------------+-------------+
  | PcaSvc                | RUNNING     |
  | PlugPlay              | RUNNING     |
  | DPS                   | RUNNING     |
  | DiagTrack             | RUNNING     |
  | SysMain               | RUNNING     |
  | Sysmon                | UNKNOWN     |
  | EventLog              | RUNNING     |
  +-----------------------+-------------+

  Monitoramento ativo (polling 500ms)
  Pressione Ctrl+C para encerrar
```

### Quando uma tentativa é detectada:

```
  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  !!                    ALERTA DETECTADO                   !!
  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  Servico: DiagTrack
  Estado: RUNNING -> STOPPED
  Hora: 2025-12-16 22:57:17.458

  >>> TENTATIVA DE DESABILITAR/PARAR DETECTADA! <<<

  [!] Processos suspeitos ativos:
      - PID: 1060   | Processo: services.exe
      - PID: 11624  | Processo: cmd.exe

  [!!!] PROCESSOS ENCONTRADOS QUE PODEM TER CAUSADO:
        >>> PID: 11624  | sc.exe
  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

---

## 🔧 Compilação (Opcional)

Se preferir compilar você mesmo:

### Visual Studio Developer Command Prompt
```batch
cl /EHsc /std:c++17 CheckServices.cpp /link advapi32.lib tdh.lib psapi.lib
```

### Requisitos
- Windows 10/11
- Visual Studio 2019+ (para compilar)
- Privilégios de Administrador (para executar)

---

## 📁 Estrutura

```
CheckServices/
├── CheckServices.cpp      # Código fonte
├── CheckServices.sln      # Solution Visual Studio
├── CheckServices.vcxproj  # Projeto Visual Studio
└── .gitignore
```

---

## 📝 Log

O programa gera um arquivo `check_services.log` no mesmo diretório com todos os eventos registrados.

---

## 📜 Licença

MIT License - Livre para uso e modificação.