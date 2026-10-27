<?php
// Authorized Hostinger HackerOne test. READ-ONLY, benign, non-destructive.
// Purpose: check whether localhost backing services (Redis/Memcached/etc) on this shared
// host are per-tenant isolated. CageFS virtualizes the filesystem but NOT network services,
// so a shared unauthenticated cache would be a cross-tenant read. We only read service
// metadata and KEY NAMES (INFO/DBSIZE/SCAN/stats) to detect missing namespacing — we never
// GET/read any value, never write, never delete.
@header('Content-Type: text/plain');
$TS = getenv('PROBE_TS') ?: date('U');
echo "== bugbounty-$TS localhost service tenancy probe (read-only) ==\n";
$uid = function_exists('posix_getuid') ? posix_getuid() : null;
$usr = ($uid!==null && function_exists('posix_getpwuid')) ? (posix_getpwuid($uid)['name'] ?? null) : null;
echo "uid=".var_export($uid,true)." user=".var_export($usr,true)." host=".gethostname()." home=".getenv('HOME')."\n";

function talk($port, $cmds, $host='127.0.0.1', $to=1.0) {
    $en=null; $es=null;
    $fp=@fsockopen($host,$port,$en,$es,$to);
    if(!$fp) return "  [$host:$port] closed/refused (errno=$en $es)\n";
    stream_set_timeout($fp,1);
    $o="  [$host:$port] OPEN\n";
    foreach($cmds as $c){
        fwrite($fp,$c."\r\n"); usleep(150000);
        $r=fread($fp,4096);
        $o.="   > ".trim($c)." => ".substr(str_replace(array("\r","\n")," ",trim((string)$r)),0,320)."\n";
    }
    fclose($fp); return $o;
}

echo "\n-- Redis :6379 (server/DBSIZE/keyspace + key NAMES via SCAN; NO values) --\n";
echo talk(6379, array("INFO server","DBSIZE","INFO keyspace","SCAN 0 COUNT 15"));
echo "\n-- Redis :6380 --\n";
echo talk(6380, array("PING","INFO keyspace","DBSIZE"));

// Memcached: stats only (counts/slab metadata, never item values)
echo "\n-- Memcached :11211 (stats only) --\n";
echo talk(11211, array("stats","stats items","stats slabs"), '127.0.0.1', 1.0);

echo "\n-- localhost internal-service sweep (connect-only) --\n";
$ports = array(3306=>'mysql',5432=>'postgres',6379=>'redis',6380=>'redis2',11211=>'memcached',
 9200=>'elasticsearch',27017=>'mongodb',2379=>'etcd',8080=>'http-alt',8000=>'http8000',
 80=>'http',443=>'https',25=>'smtp',587=>'submission',11300=>'beanstalk',5672=>'amqp',
 9000=>'php-fpm?',3000=>'node',4000=>'svc4000',6082=>'varnish-admin');
foreach($ports as $p=>$n){
    $en=null;$es=null; $fp=@fsockopen('127.0.0.1',$p,$en,$es,0.6);
    echo "  127.0.0.1:$p ($n) ".($fp?"OPEN":"-")."\n";
    if($fp) fclose($fp);
}
echo "\n== done ==\n";
