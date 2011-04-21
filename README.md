PHP SSH2
=============

We use this library to execute commands over [`Secure Shell2 for PHP`](http://www.php.net/manual/en/book.ssh2.php). 
Particularly opening an interactive shell and executing a chain of commands 
programmatically via that shell.

Example Connecting to a Unix Server
-------
`require_once 'SSH2.php';
// Test Unix
$username = 'someuser';
$password = 'somepwd';
$host = 'somenixhost.com';
$port = 22;

$ssh2 = new My_SSH2($host, $port);
$ssh2->authPassword( $username, $password);
$ssh2->setPrompt(':~#'); // Set initial expected prompt
$ssh2->openShell();
$ssh2->setPrompt("MYCUSTOMSSHPROMPT> "); // Create a unique, easily found prompt
$ssh2->exec("PS1='MYCUSTOMSSHPROMPT> '"); // Execute the command.

echo $ssh2->exec('cd /var/www') . "\n";   // Change directories.
echo $ssh2->exec('pwd') . "\n";           // Print working directory	
echo "\n===================Begin History=============\n";
echo $ssh2->getHistory();
$ssh2->disconnect();
echo "\n===================end=============\n";
exit;`

Example Connecting to a Windows Server
-------
`require_once 'SSH2.php';
// Test Unix
$username = 'someuser';
$password = 'somepwd';
$host = 'somewin32host.com';
$port = 22;

$ssh2 = new My_SSH2($host, $port);
$ssh2->authPassword( $username, $password);
$ssh2->setPrompt(':~#'); // Set initial expected prompt
$ssh2->openShell();
$ssh2->setPrompt("MYCUSTOMSSHPROMPT>"); // Create a unique, easily found prompt
$ssh2->exec("prompt MYCUSTOMSSHPROMPT$G"); // Execute the command.

echo $ssh2->exec('cd c:\\temp') . "\n";   // Change directories.
echo $ssh2->exec('chdir') . "\n";           // Print working directory	
echo "\n===================Begin History=============\n";
echo $ssh2->getHistory();
$ssh2->disconnect();
echo "\n===================end=============\n";
exit;`