#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "esp_log.h"
#include "esp_http_server.h"
#include "cJSON.h"
#include "wifi_scanner.h"
#include "attack_deauth.h"
#include "attack_deauth_detector.h"
#include "attack_beacon_spam.h"
#include "attack_dos.h"
#include "attack_handshake.h"
#include "attack_pmkid.h"
#include "attack_probe.h"
#include "attack_eviltwin.h"
#include "attack.h"

static const char *TAG = "WEB_SERVER";

#define USERNAME "omega"
#define PASSWORD "solutions123"

static int attack_duration_minutes = 0;
static time_t attack_start_time = 0;
static bool attack_timer_active = false;
static char current_target_ssid[64] = {0};
static char current_target_bssid[18] = {0};

// Login Page
const char* login_html = 
"<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>"
"<title>Omega Solutions - Login</title><style>"
"*{margin:0;padding:0;box-sizing:border-box;}body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;"
"background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;justify-content:center;align-items:center;}"
".login-container{background:rgba(255,255,255,0.95);border-radius:20px;padding:40px;box-shadow:0 20px 60px rgba(0,0,0,0.3);"
"width:90%;max-width:400px;text-align:center;}.logo{font-size:48px;margin-bottom:20px;}h1{color:#333;margin-bottom:10px;}"
".subtitle{color:#666;margin-bottom:30px;}input{width:100%;padding:15px;margin:10px 0;border:2px solid #ddd;border-radius:10px;font-size:16px;}"
"input:focus{outline:none;border-color:#667eea;}button{width:100%;padding:15px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);"
"color:white;border:none;border-radius:10px;font-size:16px;cursor:pointer;}</style></head><body>"
"<div class='login-container'><div class='logo'>🔒</div><h1>Omega Solutions</h1><div class='subtitle'>Security Testing Platform</div>"
"<form method='POST' action='/login'>"
"<input type='text' name='username' placeholder='Username' required>"
"<input type='password' name='password' placeholder='Password' required>"
"<button type='submit'>Login</button>"
"</form></div></body></html>";

// Dashboard HTML (same as your working version)
const char* dashboard_html = 
"<!DOCTYPE html><html data-theme='dark'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0, user-scalable=yes'>"
"<title>Omega Solutions - Complete Security Suite</title><style>"
":root{--bg-primary:#0a0e27;--bg-secondary:#16213e;--text-primary:#ffffff;--text-secondary:#a0a0a0;"
"--card-bg:rgba(255,255,255,0.08);--border-color:rgba(255,255,255,0.1);"
"--gradient-1:linear-gradient(135deg,#667eea 0%,#764ba2 100%);"
"--gradient-2:linear-gradient(135deg,#f093fb 0%,#f5576c 100%);"
"--gradient-3:linear-gradient(135deg,#4facfe 0%,#00f2fe 100%);"
"--gradient-4:linear-gradient(135deg,#43e97b 0%,#38f9d7 100%);"
"--danger:#ff4757;--success:#00d25b;--warning:#ffb400;}"
"[data-theme='light']{--bg-primary:#f0f2f5;--bg-secondary:#ffffff;--text-primary:#1a1a2e;--text-secondary:#666666;--card-bg:#ffffff;--border-color:#e0e0e0;}"
"*{margin:0;padding:0;box-sizing:border-box;}"
"body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:var(--bg-primary);color:var(--text-primary);padding:15px;min-height:100vh;}"
".container{max-width:1400px;margin:0 auto;}"
".header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;padding:15px 20px;background:var(--bg-secondary);border-radius:15px;}"
".logo-section{display:flex;align-items:center;gap:15px;}.logo{font-size:32px;}"
".title h1{font-size:20px;background:var(--gradient-1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}"
".subtitle{font-size:11px;color:var(--text-secondary);}"
".theme-toggle{background:var(--card-bg);border:1px solid var(--border-color);padding:8px 15px;border-radius:20px;cursor:pointer;margin-left:10px;}"
".icon-menu{display:flex;justify-content:center;gap:20px;margin-bottom:25px;padding:15px;background:var(--bg-secondary);border-radius:15px;flex-wrap:wrap;}"
".icon-item{text-align:center;cursor:pointer;padding:10px 20px;border-radius:12px;transition:all 0.3s ease;}"
".icon-item:hover{transform:translateY(-5px);background:var(--card-bg);}"
".icon-item.active{background:var(--gradient-1);}"
".icon-large{font-size:32px;display:block;margin-bottom:8px;}"
".icon-label{font-size:11px;font-weight:bold;}"
".attacks-container{display:none;margin-bottom:20px;}"
".attacks-container.active{display:block;}"
".attack-buttons{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;}"
".attack-card{background:var(--card-bg);border:1px solid var(--border-color);border-radius:10px;padding:10px 15px;cursor:pointer;transition:all 0.3s ease;text-align:center;flex:1;min-width:90px;}"
".attack-card:hover{transform:translateY(-3px);background:var(--gradient-2);}"
".attack-card.selected{background:var(--gradient-1);border-color:transparent;}"
".attack-name{font-size:13px;font-weight:bold;}"
".attack-status{font-size:9px;margin-top:5px;color:var(--text-secondary);}"
".grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;}"
".card{background:var(--card-bg);border-radius:15px;padding:20px;border:1px solid var(--border-color);}"
".card h2{font-size:18px;margin-bottom:15px;background:var(--gradient-3);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}"
".scan-controls{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;}"
".btn{background:var(--gradient-4);color:#000;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-weight:bold;}"
".btn:hover{transform:translateY(-2px);}"
".btn-danger{background:var(--danger);color:#fff;}"
".btn-stop{background:var(--gradient-2);color:#fff;}"
".btn-warning{background:var(--warning);color:#000;}"
".dos-options, .handshake-options{display:flex;gap:10px;margin:10px 0;flex-wrap:wrap;}"
".dos-btn, .handshake-btn{padding:8px 15px;background:var(--card-bg);border:1px solid var(--border-color);border-radius:8px;cursor:pointer;}"
".dos-btn.active, .handshake-btn.active{background:var(--gradient-1);}"
".time-input-area{display:flex;gap:10px;margin:15px 0;align-items:center;flex-wrap:wrap;}"
".time-input{background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-primary);padding:10px;border-radius:8px;width:100px;text-align:center;}"
".attack-panel{background:rgba(255,71,87,0.1);border:1px solid var(--danger);border-radius:10px;padding:15px;margin-top:15px;}"
".beacon-config, .dos-config, .handshake-config{background:rgba(0,210,91,0.1);border:1px solid var(--success);border-radius:10px;padding:15px;margin-top:15px;}"
".status{padding:12px;margin:15px 0;border-radius:10px;text-align:center;font-weight:bold;}"
".status.idle{background:rgba(0,210,91,0.2);border:1px solid var(--success);color:var(--success);}"
".status.attacking{background:rgba(255,71,87,0.2);border:1px solid var(--danger);color:var(--danger);animation:pulse 1s infinite;}"
".log-area{background:#000;color:#00ff00;padding:15px;height:250px;overflow-y:scroll;font-family:'Courier New',monospace;font-size:11px;border-radius:10px;}"
".log-entry{margin:3px 0;padding:3px 5px;border-left:3px solid var(--success);}"
".log-entry.attack{border-left-color:var(--danger);color:#ff6b6b;}"
".log-entry.warning{border-left-color:var(--warning);color:#ffd93d;}"
".log-entry.success{border-left-color:var(--success);color:#6bcb77;}"
"table{width:100%;border-collapse:collapse;margin-top:10px;font-size:12px;}"
"th,td{padding:8px;text-align:left;border-bottom:1px solid var(--border-color);}"
"th{background:var(--gradient-1);color:#fff;}"
"tr:hover{background:rgba(255,255,255,0.05);}"
".select-btn{background:var(--gradient-3);color:#fff;border:none;padding:5px 10px;border-radius:5px;cursor:pointer;font-size:11px;}"
".selected-network{background:var(--gradient-3);padding:10px;border-radius:8px;margin:10px 0;text-align:center;font-size:13px;}"
"@keyframes pulse{0%{opacity:1;}50%{opacity:0.6;}100%{opacity:1;}}"
"@media(max-width:768px){.grid{grid-template-columns:1fr;}.icon-large{font-size:24px;}}"
"</style>"
"<script>"
"let selectedNetwork = null;"
"let selectedAttack = 'deauth';"
"let selectedModule = 'wifi';"
"let customTime = 2;"
"let dosMethod = 0;"
"let handshakeMethod = 0;"
""
"function toggleTheme(){var e=document.documentElement,t=e.getAttribute('data-theme')==='dark'?'light':'dark';e.setAttribute('data-theme',t);localStorage.setItem('theme',t);}"
"function logout(){window.location.href='/logout';}"
""
"function addLog(msg,type){"
"var logDiv=document.getElementById('logArea');"
"var entry=document.createElement('div');"
"entry.className='log-entry '+(type||'info');"
"entry.innerHTML='['+new Date().toLocaleTimeString()+'] '+msg;"
"logDiv.appendChild(entry);"
"logDiv.scrollTop=logDiv.scrollHeight;"
"}"
""
"function selectModule(module){"
"selectedModule=module;"
"document.querySelectorAll('.icon-item').forEach(el=>el.classList.remove('active'));"
"document.getElementById('icon-'+module).classList.add('active');"
"document.querySelectorAll('.attacks-container').forEach(el=>el.classList.remove('active'));"
"document.getElementById(module+'-attacks').classList.add('active');"
"addLog('Selected '+module.toUpperCase()+' module','info');"
"}"
""
"function selectAttack(attack){"
"selectedAttack=attack;"
"document.querySelectorAll('.attack-card').forEach(el=>el.classList.remove('selected'));"
"document.getElementById('attack-'+attack).classList.add('selected');"
"document.querySelectorAll('.attack-panel, .beacon-config, .dos-config, .handshake-config').forEach(el=>el.style.display='none');"
"if(attack==='deauth') document.getElementById('deauthPanel').style.display='block';"
"else if(attack==='beacon') document.getElementById('beaconPanel').style.display='block';"
"else if(attack==='dos') document.getElementById('dosPanel').style.display='block';"
"else if(attack==='handshake') document.getElementById('handshakePanel').style.display='block';"
"else if(attack==='pmkid') document.getElementById('pmkidPanel').style.display='block';"
"else if(attack==='probe') document.getElementById('probePanel').style.display='block';"
"else if(attack==='eviltwin') document.getElementById('eviltwinPanel').style.display='block';"
"addLog('Selected attack: '+attack.toUpperCase(),'info');"
"}"
""
"function updateCustomTime(){var val=parseInt(document.getElementById('customTimeInput').value);if(val>0&&val<=999){customTime=val;addLog('Duration set to '+customTime+' minutes','info');}}"
""
"function selectDosMethod(method){dosMethod=method;document.querySelectorAll('.dos-btn').forEach(el=>el.classList.remove('active'));event.target.classList.add('active');}"
"function selectHandshakeMethod(method){handshakeMethod=method;document.querySelectorAll('.handshake-btn').forEach(el=>el.classList.remove('active'));event.target.classList.add('active');}"
""
"async function startBeaconSpam(){var m=document.getElementById('beaconMode').value;var c=document.getElementById('beaconCount').value;addLog('Starting Beacon Spam - Mode:'+m+' Count:'+c,'attack');await fetch('/api/beacon/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:parseInt(m),count:parseInt(c)})});addLog('Beacon spam active!','success');}"
"async function stopBeaconSpam(){await fetch('/api/beacon/stop',{method:'POST'});addLog('Beacon spam stopped','warning');}"
""
"async function startDosAttack(){if(!selectedNetwork){addLog('ERROR: No network selected!','warning');return;}addLog('🚀 STARTING DoS attack on '+selectedNetwork.ssid+' (Method: '+dosMethod+')','attack');await fetch('/api/dos/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bssid:selectedNetwork.bssid,channel:selectedNetwork.channel,method:dosMethod})});addLog('DoS attack started!','success');}"
""
"async function startHandshakeCapture(){if(!selectedNetwork){addLog('ERROR: No network selected!','warning');return;}addLog('🔑 Starting Handshake capture on '+selectedNetwork.ssid,'attack');await fetch('/api/handshake/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bssid:selectedNetwork.bssid,channel:selectedNetwork.channel,method:handshakeMethod})});addLog('Handshake capture started! Waiting for EAPOL...','success');}"
""
"async function startPmkidAttack(){if(!selectedNetwork){addLog('ERROR: No network selected!','warning');return;}addLog('🔐 Starting PMKID attack on '+selectedNetwork.ssid,'attack');await fetch('/api/pmkid/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bssid:selectedNetwork.bssid,channel:selectedNetwork.channel})});addLog('PMKID attack started!','success');}"
""
"async function startProbeSniffer(){addLog('👻 Starting Probe Sniffer/Ghost AP attack','attack');await fetch('/api/probe/start',{method:'POST'});addLog('Probe sniffer active! Creating ghost APs...','success');}"
""
"async function startEvilTwin(){if(!selectedNetwork){addLog('ERROR: No network selected!','warning');return;}addLog('🎭 Starting Evil Twin attack on '+selectedNetwork.ssid,'attack');await fetch('/api/eviltwin/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bssid:selectedNetwork.bssid,ssid:selectedNetwork.ssid,channel:selectedNetwork.channel})});addLog('Evil Twin active! Waiting for victim password...','success');}"
""
"async function stopAllAttacks(){await fetch('/api/stop/all',{method:'POST'});addLog('All attacks stopped','warning');document.getElementById('statusMsg').innerHTML='⏹️ All attacks stopped';document.getElementById('attackStatus').className='status idle';}"
""
"async function scanNetworks(){addLog('Scanning for networks...','info');document.getElementById('scanBtn').disabled=true;document.getElementById('scanBtn').innerHTML='📡 Scanning...';var response=await fetch('/api/scan');var networks=await response.json();displayNetworks(networks);addLog('Found '+networks.length+' networks','success');document.getElementById('scanBtn').disabled=false;document.getElementById('scanBtn').innerHTML='📡 Scan Networks';}"
""
"function displayNetworks(networks){var tbody=document.getElementById('networksTable');tbody.innerHTML='';networks.forEach(function(net){var row=tbody.insertRow();row.insertCell(0).innerHTML=net.ssid||'<i>Hidden</i>';row.insertCell(1).innerHTML=net.bssid;row.insertCell(2).innerHTML=net.channel;row.insertCell(3).innerHTML=net.rssi+' dBm';row.insertCell(4).innerHTML=net.authmode;var actionCell=row.insertCell(5);var selectBtn=document.createElement('button');selectBtn.innerHTML='📌 Select';selectBtn.className='select-btn';selectBtn.onclick=function(){selectNetwork(net.bssid,net.ssid,net.channel);};actionCell.appendChild(selectBtn);});}"
""
"function selectNetwork(bssid,ssid,channel){selectedNetwork={bssid:bssid,ssid:ssid,channel:channel};document.getElementById('selectedDisplay').innerHTML='✅ SELECTED: '+ssid+' | '+bssid+' | CH '+channel;addLog('Target selected: '+ssid,'success');}"
""
"async function startDeauthAttack(){if(!selectedNetwork){addLog('ERROR: No network selected!','warning');return;}addLog('🚀 STARTING DEAUTH attack on '+selectedNetwork.ssid,'attack');addLog('⏱️ Duration: '+customTime+' minutes','info');var response=await fetch('/api/attack',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bssid:selectedNetwork.bssid,channel:selectedNetwork.channel,minutes:customTime})});var result=await response.json();if(result.success){document.getElementById('attackStatus').className='status attacking';document.getElementById('statusMsg').innerHTML='🔴 ATTACKING: '+selectedNetwork.ssid;addLog('✅ Attack active! Auto-stop in '+customTime+' minutes','success');}else{addLog('❌ Attack failed','warning');}}"
""
"async function stopDeauthAttack(){await fetch('/api/stop',{method:'POST'});addLog('⏹️ Deauth attack stopped','warning');document.getElementById('statusMsg').innerHTML='⏹️ Attack stopped';document.getElementById('attackStatus').className='status idle';}"
""
"async function updateStatus(){try{var response=await fetch('/api/status');var data=await response.json();if(data.attacking){document.getElementById('attackStatus').className='status attacking';document.getElementById('statusMsg').innerHTML='🔴 ATTACKING: '+data.target;if(data.remaining){var mins=Math.floor(data.remaining/60);var secs=data.remaining%60;document.getElementById('timerDisplay').innerHTML='⏱️ '+mins+'m '+secs+'s';}}else{document.getElementById('timerDisplay').innerHTML='⏱️ Idle';}}catch(e){}}"
""
"async function updateDetector(){try{var response=await fetch('/api/detector');var data=await response.json();var alertsDiv=document.getElementById('alerts');if(data.alerts&&data.alerts.length>0){alertsDiv.innerHTML=data.alerts.map(function(alert){return'<div class=\"log-entry attack\"><strong>⚠️ DEAUTH DETECTED!</strong><br>BSSID: '+alert.bssid+'<br>Frames: '+alert.count+'</div>';}).join('');addLog('⚠️ Deauth attack detected!','warning');}else{alertsDiv.innerHTML='<div class=\"log-entry\">✅ No deauth attacks detected</div>';}document.getElementById('statsTracked').innerHTML=data.tracked_bssids;}catch(e){}}"
""
"document.addEventListener('DOMContentLoaded',function(){var savedTheme=localStorage.getItem('theme')||'dark';document.documentElement.setAttribute('data-theme',savedTheme);selectModule('wifi');selectAttack('deauth');scanNetworks();setInterval(updateStatus,2000);setInterval(updateDetector,3000);});"
"</script></head><body>"
"<div class='container'>"
"<div class='header'><div class='logo-section'><div class='logo'>🛡️</div><div class='title'><h1>Omega Solutions</h1><div class='subtitle'>Complete Security Suite v4.0</div></div></div>"
"<div><button class='theme-toggle' onclick='toggleTheme()'>🌓</button><button class='theme-toggle' onclick='logout()' style='margin-left:10px'>🚪</button></div></div>"
""
"<div class='icon-menu'>"
"<div class='icon-item active' id='icon-wifi' onclick='selectModule(\"wifi\")'><span class='icon-large'>📡</span><span class='icon-label'>WIFI</span></div>"
"<div class='icon-item' id='icon-ble' onclick='selectModule(\"ble\")'><span class='icon-large'>🔵</span><span class='icon-label'>BLE</span></div>"
"<div class='icon-item' id='icon-mesh' onclick='selectModule(\"mesh\")'><span class='icon-large'>🕸️</span><span class='icon-label'>MESH</span></div>"
"</div>"
""
"<!-- WiFi Attacks -->"
"<div id='wifi-attacks' class='attacks-container active'>"
"<div class='attack-buttons'>"
"<div class='attack-card selected' id='attack-deauth' onclick='selectAttack(\"deauth\")'><div class='attack-name'>⚡ Deauth Attack</div><div class='attack-status'>Active</div></div>"
"<div class='attack-card' id='attack-beacon' onclick='selectAttack(\"beacon\")'><div class='attack-name'>📡 Beacon Spam</div><div class='attack-status'>Active</div></div>"
"<div class='attack-card' id='attack-dos' onclick='selectAttack(\"dos\")'><div class='attack-name'>💀 DoS Attack</div><div class='attack-status'>Active</div></div>"
"<div class='attack-card' id='attack-handshake' onclick='selectAttack(\"handshake\")'><div class='attack-name'>🤝 Handshake</div><div class='attack-status'>Active</div></div>"
"<div class='attack-card' id='attack-pmkid' onclick='selectAttack(\"pmkid\")'><div class='attack-name'>🔐 PMKID</div><div class='attack-status'>Active</div></div>"
"<div class='attack-card' id='attack-probe' onclick='selectAttack(\"probe\")'><div class='attack-name'>👻 Probe Sniff</div><div class='attack-status'>Active</div></div>"
"<div class='attack-card' id='attack-eviltwin' onclick='selectAttack(\"eviltwin\")'><div class='attack-name'>🎭 Evil Twin</div><div class='attack-status'>Active</div></div>"
"</div></div>"
""
"<!-- BLE Attacks -->"
"<div id='ble-attacks' class='attacks-container'><div class='attack-buttons'>"
"<div class='attack-card'><div class='attack-name'>🔍 BLE Scan</div><div class='attack-status'>Soon</div></div>"
"<div class='attack-card'><div class='attack-name'>📢 BLE Spam</div><div class='attack-status'>Soon</div></div>"
"</div></div>"
""
"<!-- Mesh Attacks -->"
"<div id='mesh-attacks' class='attacks-container'><div class='attack-buttons'>"
"<div class='attack-card'><div class='attack-name'>🔎 Mesh Scan</div><div class='attack-status'>Soon</div></div>"
"<div class='attack-card'><div class='attack-name'>🌊 Mesh Flood</div><div class='attack-status'>Soon</div></div>"
"</div></div>"
""
"<div class='grid'>"
"<div class='card'><h2>🎯 Target Selection</h2>"
"<div class='scan-controls'><button class='btn' id='scanBtn' onclick='scanNetworks()'>📡 Scan Networks</button></div>"
"<div id='selectedDisplay' class='selected-network'>⚡ No network selected</div>"
"<div style='overflow-x:auto;max-height:400px;overflow-y:auto;'><table id='networksTable'><thead><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>RSSI</th><th>Security</th><th>Action</th></tr></thead><tbody><tr><td colspan='6'>Click Scan to find networks</tbody></table></div></div>"
""
"<div class='card'><h2>⚡ Attack Controller</h2>"
""
"<!-- Deauth Attack Panel -->"
"<div id='deauthPanel' class='attack-panel'><div><strong>⏱️ Attack Duration:</strong></div><div class='time-input-area'><input type='number' id='customTimeInput' class='time-input' value='2' min='1' max='999' onchange='updateCustomTime()'><span>minutes</span><button class='btn' onclick='updateCustomTime()'>Set</button></div><div style='display:flex;gap:10px;margin-top:15px;'><button class='btn btn-danger' onclick='startDeauthAttack()' style='flex:1'>🔥 START DEAUTH</button><button class='btn btn-stop' onclick='stopDeauthAttack()' style='flex:1'>⏹️ STOP DEAUTH</button></div></div>"
""
"<!-- Beacon Spam Panel -->"
"<div id='beaconPanel' class='beacon-config' style='display:none;'><div><strong>📡 Beacon Spam:</strong></div><div class='time-input-area'><select id='beaconMode' style='padding:10px;background:var(--bg-secondary);color:var(--text-primary);border-radius:8px;'><option value='0'>Common SSIDs</option><option value='1'>Garbage SSIDs</option><option value='2'>Rick Roll</option><option value='3'>Security/Troll</option></select><input type='number' id='beaconCount' value='50' min='1' max='100' style='padding:10px;width:80px;background:var(--bg-secondary);color:var(--text-primary);border-radius:8px;'><button class='btn' onclick='startBeaconSpam()'>Start</button><button class='btn btn-stop' onclick='stopBeaconSpam()'>Stop</button></div></div>"
""
"<!-- DoS Attack Panel -->"
"<div id='dosPanel' class='dos-config' style='display:none;'><div><strong>💀 DoS Attack Methods:</strong></div><div class='dos-options'><button class='dos-btn active' onclick='selectDosMethod(0)'>Broadcast</button><button class='dos-btn' onclick='selectDosMethod(1)'>Rogue AP</button><button class='dos-btn' onclick='selectDosMethod(2)'>Combine All</button><button class='dos-btn' onclick='selectDosMethod(3)'>Super Clone</button></div><button class='btn btn-danger' onclick='startDosAttack()' style='width:100%'>🚀 START DoS</button></div>"
""
"<!-- Handshake Capture Panel -->"
"<div id='handshakePanel' class='handshake-config' style='display:none;'><div><strong>🤝 Handshake Methods:</strong></div><div class='handshake-options'><button class='handshake-btn active' onclick='selectHandshakeMethod(0)'>Broadcast</button><button class='handshake-btn' onclick='selectHandshakeMethod(1)'>Rogue AP</button><button class='handshake-btn' onclick='selectHandshakeMethod(2)'>Passive</button></div><button class='btn btn-danger' onclick='startHandshakeCapture()' style='width:100%'>🔑 START CAPTURE</button></div>"
""
"<!-- PMKID Attack Panel -->"
"<div id='pmkidPanel' class='attack-panel' style='display:none;'><button class='btn btn-danger' onclick='startPmkidAttack()' style='width:100%'>🔐 START PMKID ATTACK</button></div>"
""
"<!-- Probe Sniffer Panel -->"
"<div id='probePanel' class='attack-panel' style='display:none;'><button class='btn btn-danger' onclick='startProbeSniffer()' style='width:100%'>👻 START PROBE SNIFFER</button></div>"
""
"<!-- Evil Twin Panel -->"
"<div id='eviltwinPanel' class='attack-panel' style='display:none;'><button class='btn btn-danger' onclick='startEvilTwin()' style='width:100%'>🎭 START EVIL TWIN</button></div>"
""
"<div id='attackStatus' class='status idle'><span id='statusMsg'>🟢 System Ready</span> | <span id='timerDisplay'>⏱️ Idle</span></div>"
"</div></div>"
""
"<div class='card'><h2>🛡️ Threat Detection</h2><div><span style='background:var(--gradient-1);padding:5px 10px;border-radius:20px;'>Tracking: <span id='statsTracked'>0</span> BSSIDs</span></div><div id='alerts' style='margin-top:10px;'></div></div>"
"<div class='card'><h2>📋 Attack Log Terminal</h2><div id='logArea' class='log-area'></div></div>"
"<div style='text-align:center;margin-top:10px;'><button class='btn btn-stop' onclick='stopAllAttacks()'>🛑 STOP ALL ATTACKS</button></div>"
"</div></body></html>";

// Timer task for deauth
static void attack_timer_task(void *pvParameters) {
    while (attack_timer_active) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        int remaining = (attack_duration_minutes * 60) - (time(NULL) - attack_start_time);
        if (remaining <= 0 && attack_duration_minutes > 0) {
            attack_timer_active = false;
            stop_deauth_attack();
            break;
        }
    }
    vTaskDelete(NULL);
}

// ============ LOGIN HANDLERS ============
static esp_err_t login_post_handler(httpd_req_t *req) {
    char content[256] = {0};
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    
    char username[32] = {0}, password[32] = {0};
    char *user = strstr(content, "username=");
    if (user) { user += 9; char *end = strchr(user, '&'); if (end) strncpy(username, user, end - user); else strcpy(username, user); }
    char *pass = strstr(content, "password=");
    if (pass) { pass += 9; char *end = strchr(pass, '&'); if (end) strncpy(password, pass, end - pass); else strcpy(password, pass); }
    
    if (strcmp(username, USERNAME) == 0 && strcmp(password, PASSWORD) == 0) {
        httpd_resp_set_hdr(req, "Set-Cookie", "session=authenticated; path=/");
        httpd_resp_set_hdr(req, "Location", "/dashboard");
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_send(req, "", 0);
    } else {
        httpd_resp_set_hdr(req, "Location", "/login?error=1");
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_send(req, "", 0);
    }
    return ESP_OK;
}

static esp_err_t dashboard_handler(httpd_req_t *req) {
    char cookie[100] = {0};
    httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie));
    if (!strstr(cookie, "session=authenticated")) {
        httpd_resp_set_hdr(req, "Location", "/login");
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_send(req, "", 0);
        return ESP_OK;
    }
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, dashboard_html, strlen(dashboard_html));
    return ESP_OK;
}

static esp_err_t login_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, login_html, strlen(login_html));
    return ESP_OK;
}

static esp_err_t logout_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Set-Cookie", "session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT");
    httpd_resp_set_hdr(req, "Location", "/login");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_send(req, "", 0);
    return ESP_OK;
}

static esp_err_t root_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Location", "/login");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_send(req, "", 0);
    return ESP_OK;
}

// ============ API HANDLERS ============
static esp_err_t scan_api_handler(httpd_req_t *req) {
    char cookie[100] = {0};
    httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie));
    if (!strstr(cookie, "session=authenticated")) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    int ap_count = 0;
    wifi_ap_record_t *ap_records = scan_networks(&ap_count);
    if (ap_records == NULL) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Scan failed");
        return ESP_FAIL;
    }
    cJSON *root = cJSON_CreateArray();
    for (int i = 0; i < ap_count; i++) {
        if (ap_records[i].ssid[0] == 0) break;
        cJSON *network = cJSON_CreateObject();
        cJSON_AddStringToObject(network, "ssid", (char*)ap_records[i].ssid);
        char bssid_str[18];
        snprintf(bssid_str, sizeof(bssid_str), MACSTR, MAC2STR(ap_records[i].bssid));
        cJSON_AddStringToObject(network, "bssid", bssid_str);
        cJSON_AddNumberToObject(network, "channel", ap_records[i].primary);
        cJSON_AddNumberToObject(network, "rssi", ap_records[i].rssi);
        const char *auth = "Open";
        if (ap_records[i].authmode == WIFI_AUTH_WEP) auth = "WEP";
        else if (ap_records[i].authmode == WIFI_AUTH_WPA_PSK) auth = "WPA";
        else if (ap_records[i].authmode == WIFI_AUTH_WPA2_PSK) auth = "WPA2";
        else if (ap_records[i].authmode == WIFI_AUTH_WPA_WPA2_PSK) auth = "WPA/WPA2";
        cJSON_AddStringToObject(network, "authmode", auth);
        cJSON_AddItemToArray(root, network);
    }
    free(ap_records);
    char *response = cJSON_Print(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response, strlen(response));
    cJSON_Delete(root);
    free(response);
    return ESP_OK;
}

static esp_err_t attack_api_handler(httpd_req_t *req) {
    char cookie[100] = {0};
    httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie));
    if (!strstr(cookie, "session=authenticated")) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    cJSON *bssid_json = cJSON_GetObjectItem(root, "bssid");
    cJSON *channel_json = cJSON_GetObjectItem(root, "channel");
    cJSON *minutes_json = cJSON_GetObjectItem(root, "minutes");
    
    if (!bssid_json || !channel_json) {
        cJSON_Delete(root);
        return ESP_FAIL;
    }
    
    uint8_t bssid[6];
    sscanf(bssid_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]);
    
    start_deauth_attack(bssid, channel_json->valueint);
    
    if (minutes_json && minutes_json->valueint > 0) {
        attack_duration_minutes = minutes_json->valueint;
        attack_start_time = time(NULL);
        attack_timer_active = true;
        xTaskCreate(attack_timer_task, "attack_timer", 2048, NULL, 5, NULL);
    }
    
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);
    char *response_str = cJSON_Print(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    cJSON_Delete(root);
    cJSON_Delete(response);
    free(response_str);
    return ESP_OK;
}

static esp_err_t beacon_start_handler(httpd_req_t *req) {
    char cookie[100] = {0};
    httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie));
    if (!strstr(cookie, "session=authenticated")) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    char content[100];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    
    cJSON *mode_json = cJSON_GetObjectItem(root, "mode");
    cJSON *count_json = cJSON_GetObjectItem(root, "count");
    
    int mode = mode_json ? mode_json->valueint : 0;
    int count = count_json ? count_json->valueint : 50;
    
    attack_beacon_spam_start(count, mode);
    
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);
    char *response_str = cJSON_Print(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    cJSON_Delete(root);
    cJSON_Delete(response);
    free(response_str);
    return ESP_OK;
}

static esp_err_t beacon_stop_handler(httpd_req_t *req) {
    attack_beacon_spam_stop();
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);
    char *response_str = cJSON_Print(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    cJSON_Delete(response);
    free(response_str);
    return ESP_OK;
}

static esp_err_t stop_api_handler(httpd_req_t *req) {
    attack_timer_active = false;
    stop_deauth_attack();
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);
    char *response_str = cJSON_Print(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    cJSON_Delete(response);
    free(response_str);
    return ESP_OK;
}

static esp_err_t status_api_handler(httpd_req_t *req) {
    char cookie[100] = {0};
    httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie));
    if (!strstr(cookie, "session=authenticated")) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "attacking", is_attack_active());
    if (is_attack_active()) {
        char target[18];
        get_attack_target(target);
        cJSON_AddStringToObject(response, "target", target);
        if (attack_timer_active) {
            int elapsed = time(NULL) - attack_start_time;
            int remaining = (attack_duration_minutes * 60) - elapsed;
            if (remaining > 0) cJSON_AddNumberToObject(response, "remaining", remaining);
        }
    }
    char *response_str = cJSON_Print(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    cJSON_Delete(response);
    free(response_str);
    return ESP_OK;
}

static esp_err_t detector_api_handler(httpd_req_t *req) {
    char cookie[100] = {0};
    httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie));
    if (!strstr(cookie, "session=authenticated")) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    const deauth_detector_status_t *status = deauth_detector_get_status();
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "running", status->running);
    cJSON_AddNumberToObject(root, "tracked_bssids", status->count);
    cJSON *alerts = cJSON_CreateArray();
    for (int i = 0; i < status->count; i++) {
        if (status->entries[i].alerting) {
            cJSON *alert = cJSON_CreateObject();
            char bssid_str[18];
            snprintf(bssid_str, sizeof(bssid_str), MACSTR, MAC2STR(status->entries[i].bssid));
            cJSON_AddStringToObject(alert, "bssid", bssid_str);
            cJSON_AddNumberToObject(alert, "count", status->entries[i].count);
            cJSON_AddItemToArray(alerts, alert);
        }
    }
    cJSON_AddItemToObject(root, "alerts", alerts);
    char *response_str = cJSON_Print(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    cJSON_Delete(root);
    free(response_str);
    return ESP_OK;
}

// New API handlers
static esp_err_t dos_start_handler(httpd_req_t *req) {
    char cookie[100] = {0};
    httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie));
    if (!strstr(cookie, "session=authenticated")) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    
    cJSON *bssid_json = cJSON_GetObjectItem(root, "bssid");
    cJSON *method_json = cJSON_GetObjectItem(root, "method");
    
    if (!bssid_json) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing bssid");
        return ESP_FAIL;
    }
    
    uint8_t bssid[6];
    sscanf(bssid_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]);
    
    // Create attack config and persistent AP record for the attack
    attack_config_t attack_config = {0};
    attack_config.target_count = 1;
    attack_config.method = method_json ? method_json->valueint : 0;

    // Allocate persistent wifi_ap_record_t and pointer array on heap so timers/tasks
    // started by the attack code can safely reference the record after this handler returns.
    wifi_ap_record_t *ap = malloc(sizeof(wifi_ap_record_t));
    if (!ap) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Allocation failed");
        return ESP_FAIL;
    }
    memset(ap, 0, sizeof(*ap));
    memcpy(ap->bssid, bssid, 6);
    strncpy((char *)ap->ssid, "unknown", sizeof(ap->ssid));
    ap->primary = 1; // default channel if not provided

    wifi_ap_record_t **ap_ptrs = malloc(sizeof(wifi_ap_record_t *));
    if (!ap_ptrs) {
        free(ap);
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Allocation failed");
        return ESP_FAIL;
    }
    ap_ptrs[0] = ap;

    attack_config.ap_records = (const wifi_ap_record_t **)ap_ptrs;

    ESP_LOGI(TAG, "Starting DoS attack with method: %d", attack_config.method);
    attack_dos_start(&attack_config);
    
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);
    char *response_str = cJSON_Print(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    cJSON_Delete(root);
    cJSON_Delete(response);
    free(response_str);
    return ESP_OK;
}

static esp_err_t handshake_start_handler(httpd_req_t *req) {
    char cookie[100] = {0};
    httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie));
    if (!strstr(cookie, "session=authenticated")) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    
    cJSON *bssid_json = cJSON_GetObjectItem(root, "bssid");
    cJSON *channel_json = cJSON_GetObjectItem(root, "channel");
    cJSON *method_json = cJSON_GetObjectItem(root, "method");
    
    if (!bssid_json || !channel_json) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing bssid or channel");
        return ESP_FAIL;
    }
    
    // Create ap_record from bssid and channel
    wifi_ap_record_t ap_record = {0};
    sscanf(bssid_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &ap_record.bssid[0], &ap_record.bssid[1], &ap_record.bssid[2],
           &ap_record.bssid[3], &ap_record.bssid[4], &ap_record.bssid[5]);
    ap_record.primary = channel_json->valueint;
    
attack_config_t attack_config = {0};

const wifi_ap_record_t *ap_list[1];
ap_list[0] = &ap_record;

attack_config.target_count = 1;
attack_config.ap_records = ap_list;
attack_config.method = method_json ? method_json->valueint : 0;
    
    ESP_LOGI(TAG, "Starting Handshake capture with method: %d", attack_config.method);
    attack_handshake_start(&attack_config);
    
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);
    char *response_str = cJSON_Print(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    cJSON_Delete(root);
    cJSON_Delete(response);
    free(response_str);
    return ESP_OK;
}

static esp_err_t pmkid_start_handler(httpd_req_t *req) {
    char cookie[100] = {0};
    httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie));
    if (!strstr(cookie, "session=authenticated")) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    
    cJSON *bssid_json = cJSON_GetObjectItem(root, "bssid");
    
    if (!bssid_json) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing bssid");
        return ESP_FAIL;
    }
    
    attack_config_t attack_config = {0};
    attack_config.target_count = 1;
    
    ESP_LOGI(TAG, "Starting PMKID attack");
    attack_pmkid_start(&attack_config);
    
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);
    char *response_str = cJSON_Print(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    cJSON_Delete(root);
    cJSON_Delete(response);
    free(response_str);
    return ESP_OK;
}

static esp_err_t probe_start_handler(httpd_req_t *req) {
    char cookie[100] = {0};
    httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie));
    if (!strstr(cookie, "session=authenticated")) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Starting Probe Sniffer");
    attack_probe_start(NULL);
    
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);
    char *response_str = cJSON_Print(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    cJSON_Delete(response);
    free(response_str);
    return ESP_OK;
}

static esp_err_t eviltwin_start_handler(httpd_req_t *req) {
    char cookie[100] = {0};
    httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie));
    if (!strstr(cookie, "session=authenticated")) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    
    cJSON *bssid_json = cJSON_GetObjectItem(root, "bssid");
    cJSON *ssid_json = cJSON_GetObjectItem(root, "ssid");
    
    if (!bssid_json || !ssid_json) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing bssid or ssid");
        return ESP_FAIL;
    }
    
    // Create a fake ap_record
    wifi_ap_record_t ap_record = {0};
    sscanf(bssid_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &ap_record.bssid[0], &ap_record.bssid[1], &ap_record.bssid[2],
           &ap_record.bssid[3], &ap_record.bssid[4], &ap_record.bssid[5]);
    strncpy((char*)ap_record.ssid, ssid_json->valuestring, 32);
    
    ESP_LOGI(TAG, "Starting Evil Twin attack on SSID: %s", ap_record.ssid);
    attack_method_evil_twin(&ap_record);
    
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);
    char *response_str = cJSON_Print(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    cJSON_Delete(root);
    cJSON_Delete(response);
    free(response_str);
    return ESP_OK;
}

static esp_err_t stop_all_handler(httpd_req_t *req) {
    attack_timer_active = false;
    stop_deauth_attack();
    attack_beacon_spam_stop();
    attack_dos_stop();
    attack_handshake_stop();
    attack_pmkid_stop();
    attack_probe_stop();
    attack_method_evil_twin_stop();
    
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);
    char *response_str = cJSON_Print(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    cJSON_Delete(response);
    free(response_str);
    return ESP_OK;
}

void start_web_server(void) {
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.max_uri_handlers = 30;
    
    if (httpd_start(&server, &config) == ESP_OK) {
        // Register all URI handlers
        httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = root_handler };
        httpd_register_uri_handler(server, &root);
        httpd_uri_t login = { .uri = "/login", .method = HTTP_GET, .handler = login_handler };
        httpd_register_uri_handler(server, &login);
        httpd_uri_t login_post = { .uri = "/login", .method = HTTP_POST, .handler = login_post_handler };
        httpd_register_uri_handler(server, &login_post);
        httpd_uri_t dashboard = { .uri = "/dashboard", .method = HTTP_GET, .handler = dashboard_handler };
        httpd_register_uri_handler(server, &dashboard);
        httpd_uri_t logout = { .uri = "/logout", .method = HTTP_GET, .handler = logout_handler };
        httpd_register_uri_handler(server, &logout);
        httpd_uri_t scan = { .uri = "/api/scan", .method = HTTP_GET, .handler = scan_api_handler };
        httpd_register_uri_handler(server, &scan);
        httpd_uri_t attack = { .uri = "/api/attack", .method = HTTP_POST, .handler = attack_api_handler };
        httpd_register_uri_handler(server, &attack);
        httpd_uri_t stop = { .uri = "/api/stop", .method = HTTP_POST, .handler = stop_api_handler };
        httpd_register_uri_handler(server, &stop);
        httpd_uri_t status = { .uri = "/api/status", .method = HTTP_GET, .handler = status_api_handler };
        httpd_register_uri_handler(server, &status);
        httpd_uri_t detector = { .uri = "/api/detector", .method = HTTP_GET, .handler = detector_api_handler };
        httpd_register_uri_handler(server, &detector);
        httpd_uri_t beacon_start = { .uri = "/api/beacon/start", .method = HTTP_POST, .handler = beacon_start_handler };
        httpd_register_uri_handler(server, &beacon_start);
        httpd_uri_t beacon_stop = { .uri = "/api/beacon/stop", .method = HTTP_POST, .handler = beacon_stop_handler };
        httpd_register_uri_handler(server, &beacon_stop);
        httpd_uri_t dos_start = { .uri = "/api/dos/start", .method = HTTP_POST, .handler = dos_start_handler };
        httpd_register_uri_handler(server, &dos_start);
        httpd_uri_t handshake_start = { .uri = "/api/handshake/start", .method = HTTP_POST, .handler = handshake_start_handler };
        httpd_register_uri_handler(server, &handshake_start);
        httpd_uri_t pmkid_start = { .uri = "/api/pmkid/start", .method = HTTP_POST, .handler = pmkid_start_handler };
        httpd_register_uri_handler(server, &pmkid_start);
        httpd_uri_t probe_start = { .uri = "/api/probe/start", .method = HTTP_POST, .handler = probe_start_handler };
        httpd_register_uri_handler(server, &probe_start);
        httpd_uri_t eviltwin_start = { .uri = "/api/eviltwin/start", .method = HTTP_POST, .handler = eviltwin_start_handler };
        httpd_register_uri_handler(server, &eviltwin_start);
        httpd_uri_t stop_all = { .uri = "/api/stop/all", .method = HTTP_POST, .handler = stop_all_handler };
        httpd_register_uri_handler(server, &stop_all);
        
        ESP_LOGI(TAG, "==========================================");
        ESP_LOGI(TAG, "Omega Solutions - Complete Security Suite v4.0");
        ESP_LOGI(TAG, "Web server started! Open http://192.168.4.1");
        ESP_LOGI(TAG, "Username: omega | Password: solutions123");
        ESP_LOGI(TAG, "Available Attacks: Deauth, Beacon, DoS, Handshake, PMKID, Probe, EvilTwin");
        ESP_LOGI(TAG, "==========================================");
    }
}