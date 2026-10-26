<?php
// bugbounty CageFS cross-tenant boundary probe v2 (authorized, own account). Benign READS only;
// reports readability/structure, never dumps another tenant's secret contents.
header('Content-Type: text/plain');
function u(){ return function_exists('posix_geteuid')&&function_exists('posix_getpwuid') ? @posix_getpwuid(posix_geteuid())['name'] : 'uid'.getmyuid(); }
$me=u(); $mypid=getmypid();
echo "== bugbounty CageFS boundary probe v2 ==\n";
echo "euid_user=$me uid=".getmyuid()." pid=$mypid cwd=".getcwd()."\n";
echo "open_basedir=".var_export(ini_get('open_basedir'),true)."\n\n";

echo "-- /proc visibility (hidepid? can I see OTHER tenants' processes?) --\n";
$pr=@scandir('/proc'); $pids=is_array($pr)?array_values(array_filter($pr,'ctype_digit')):array();
echo "pids_visible=".count($pids)." (mine=$mypid)\n";
$leak=0;
foreach($pids as $pp){
  if($pp==$mypid) continue;
  $env=@file_get_contents("/proc/$pp/environ",false,null,0,4);
  $rp =@file_get_contents("/proc/$pp/root/etc/passwd",false,null,0,4);
  $cmd=@file_get_contents("/proc/$pp/cmdline",false,null,0,40);
  if($env!==false || $rp!==false){
    echo "  *** pid $pp CROSS-PROC READ: environ=".($env!==false?"YES":"-")." root/etc/passwd=".($rp!==false?"YES":"-")." cmd=".preg_replace('/\x00/',' ',$cmd??'')." ***\n";
    if(++$leak>=5) { echo "  (stopping at 5)\n"; break; }
  }
}
if($leak==0) echo "  no other-process reads succeeded\n";

echo "\n-- paths CageFS may NOT virtualize --\n";
foreach(array('/proc/1/root/home','/proc/1/root/etc/passwd','/sys/class/net','/proc/mounts','/etc/cagefs','/var/lib/mysql','/home/../home') as $p){
  $t=@scandir($p); $f=@file_get_contents($p,false,null,0,4);
  echo "  $p : scandir=".($t===false?"DENIED":("OK(".count($t).")")).(is_array($t)&&count($t)>0?(" sample=".implode(",",array_slice(array_filter($t,fn($x)=>$x!=='.'&&$x!=='..'),0,6))):"")."\n";
}

echo "\n-- /proc/mounts (reveals other users' mounts?) --\n";
$m=@file('/proc/mounts'); echo $m===false?"  DENIED\n":("  lines=".count($m)." home-mounts=".implode(" | ", array_slice(array_values(array_filter(array_map('trim',$m), fn($l)=>strpos($l,'/home/')!==false)),0,5))."\n");

echo "\n-- shared MySQL reachable? (connect, SHOW DATABASES = do I see others'?) --\n";
if(function_exists('mysqli_connect')){
  // try socket/localhost with no creds (just reachability + error reveals server)
  $c=@mysqli_connect('localhost','probe_nouser','','');
  echo "  localhost no-cred: ".(mysqli_connect_errno()?("err ".mysqli_connect_error()):"CONNECTED?!")."\n";
} else echo "  mysqli not available\n";
echo "== end ==\n";
