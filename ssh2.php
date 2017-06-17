<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * SSH2 driver class.
 *
 * The SSH2 class is a concrete implementation based on
 * PHP Secure Shell2 Bindings to the libssh2 library. The
 * shell portion is based on the Telnet class developed
 * by Dalibor Andzakovic <dali@swerve.co.nz>
 *
 * PHP version 5
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330,Boston,MA 02111-1307 USA
 *
 * @category  Net
 *
 * @author    Rob 'Bubba' Hines <rob@stechstudio.com>
 * @copyright 2010 Signature Tech Studio
 * @license   GNU/LGPL v2.1
 *
 * @link      http://stechstudio.com/packages/SSH2
 * @link      http://www.php.net/manual/en/book.ssh2.php
 * @link	  http://www.dali.net.nz/Telnet.class.php.txt
 */
class ssh2
{
    // Remote Host
    private $_host;

    // Remote Port
    private $_port;

    // Used for handling lag
    private $_timeout;

    // Holds our connection object
    private $_connection = null;

    // Holds our sftp object
    private $_sftp = null;

    // Manages the buffer for us
    private $_buffer = null;

    // Maintains a complete history of the shell
    private $_history = '';

    // Holds the shell stream
    private $_shell = null;

    // Allows us to define a prompt to look for
    private $_prompt = '>';

    // We use the dumb terminal to avoid excessive escape characters
    // in windows SSH sessions.
    private $_term_type = 'dumb';

    // may be passed as an associative array of name/value
    // pairs to set in the target environment.
    private $_env = null;

    // Width of the virtual terminal.
    private $_width = 80;

    // Height of the virtual terminal.
    private $_height = 40;

    // should be one of SSH2_TERM_UNIT_CHARS or SSH2_TERM_UNIT_PIXELS.
    private $_width_height_type = SSH2_TERM_UNIT_CHARS;

    private $_debug = true;
    private $_debugLog = '/var/log/sshdebug.log';

    /**
     * These are telnet characters that might be of use for us.
     */
    private $_NULL;
    private $_DC1;
    private $_WILL;
    private $_WONT;
    private $_DO;
    private $_DONT;
    private $_IAC;
    private $_ESC;

    // Error
    const SSH_ERROR = false;

    // No error
    const SSH_OK = true;

    /**
     * Constructor. Initialises host, port and timeout parameters
     * defaults to localhost port 22 (standard SSH port).
     *
     * @param string $host    Host name or IP addres
     * @param int    $port    TCP port number
     * @param int    $timeout Connection timeout in seconds
     *
     * @return void
     */
    public function __construct($host = false, $port = '22', $timeout = 10)
    {
        if (!function_exists('ssh2_connect')) {
            throw new Exception("FATAL: ssh2_connect function doesn't exist!");
        }

        $this->_host = $host;
        $this->_port = $port;
        $this->_timeout = $timeout;

        $this->_NULL = chr(0);
        $this->_DC1 = chr(17);
        $this->_WILL = chr(251);
        $this->_WONT = chr(252);
        $this->_DO = chr(253);
        $this->_DONT = chr(254);
        $this->_IAC = chr(255);
        $this->_ESC = chr(27);

        if ($this->_host) {
            $this->connect();
        }
    }

    /**
     * Destructor. Cleans up socket connection and command buffer.
     *
     * @return void
     */
    public function __destruct()
    {
        // cleanup resources
        $this->disconnect();
        $this->_buffer = null;
    }

    /**
     * Attempts connection to remote host. Returns TRUE if sucessful.
     *
     * @param string $host      Host name or IP address
     * @param string $port      Port to connect ot
     * @param array  $methods   Methods may be an associative array with any of the ssh2 connect parameters
     * @param array  $callbacks May be an associative array with any of the ssh2 connect parameters
     *
     * @return bool
     */
    public function connect($host = null, $port = null, $methods = null, $callbacks = null)
    {
        // Set the Host if we got a new one.
        if ($host != null) {
            $this->_host = $host;
        }

        // Set the Port if we got a new one.
        if ($port != null) {
            $this->_port = $port;
        }

        // Set the methods array
        if ($methods != null) {
            if (!is_array($methods)) {
                $methods = [];
            }
        } else {
            $methods = [];
        }

        // Set any callbacks
        if ($callbacks != null) {
            if (!is_array($callbacks)) {
                $callbacks = ['disconnect' => 'Executor::disconnect_cb'];
            }
        } else {
            $callbacks = ['disconnect' => 'SSH2::disconnect_cb'];
        }

        // Lets make the connection
        $this->_connection = ssh2_connect($this->_host, $this->_port, $methods, $callbacks);

        // Throw an exception if there are errors.
        if (!$this->_connection) {
            throw new Exception("ERROR: Failed connecting to {$this->host} on port {$this->port}");
        }

        return self::SSH_OK;
    }

    public function isConnected()
    {
        return (bool) $this->_connection;
    }

    /**
     * Notify the user if the connection terminates.
     *
     * @param string $reason
     * @param string $message
     * @param string $language
     *
     * @return void
     */
    public static function disconnect_cb($reason, $message, $language)
    {
        printf("SSH disconnected with reason code [%d] and message: %s\n", $reason, $message);
    }

    /**
     * Closes SSH socket.
     *
     * @return bool
     */
    public function disconnect()
    {
        $this->_connection = null;

        return self::SSH_OK;
    }

    /**
     * Attempts login to remote host.
     *
     * @param string $username Username
     * @param string $password Password
     *
     * @throws exception
     *
     * @return bool
     */
    public function authPassword($username = '', $password = '')
    {
        if ($username != '') {
            $this->_user = $username;
        }
        if ($password != '') {
            $this->_password = $password;
        }
        if (!ssh2_auth_password($this->_connection, $this->_user, $this->_password)) {
            throw new Exception("Password Authentication failed for $this->_user");
        }

        return self::SSH_OK;
    }

    /**
     * Sets the string of characters to respond to.
     * This should be set to the last character of the command line prompt.
     *
     * @param string $s String we will respond to
     *
     * @return bool
     */
    public function setPrompt($s = '>')
    {
        $this->_prompt = $s;

        return self::SSH_OK;
    }

    /**
     * Clears internal command buffer.
     *
     * @return void
     */
    private function clearBuffer()
    {
        $this->_buffer = '';
    }

    /**
     * Opens a shell over SSH for us to send commands and recieve responses from.
     *
     * @param string $termType The Terminal Type we will be using
     * @param array  $env      Name/Value array of environment variables to set
     * @param string $width    Width of the terminal
     * @param string $height   Height of the terminal
     * @param string $whType   Should be one of SSH2_TERM_UNIT_CHARS or SSH2_TERM_UNIT_PIXELS
     *
     * @throws exception
     *
     * @return bool
     */
    public function openShell($termType = null, $env = null, $width = null, $height = null, $whType = null)
    {
        // Set a new term type?
        if ($termType != null) {
            $this->_term_type = $termType;
        }

        // Set any new environment variables
        if ($env != null) {
            if (!is_array($this->_env)) {
                $this->_env = null;
            } else {
                $this->_env = $env;
            }
        }
        // Set a new width?
        if ($width != null) {
            $this->_width = $width;
        }

        // Set a new Height?
        if ($height != null) {
            $this->_height = $height;
        }

        // Set a new Term Unit?
        if ($whType != null) {
            $this->_width_height_type = $whType;
        }

        // Create a SSH Shell
        if (!($this->_shell = ssh2_shell($this->_connection,
                                          $this->_term_type,
                                          $this->_env,
                                          $this->_width,
                                          $this->_height,
                                          $this->_width_height_type))) {
            throw new Exception('FATAL: unable to establish shell');
        } else {
            stream_set_blocking($this->_shell, true);
            usleep(3500);
            // get rid of the initial login stuff
            // This will still be written to the
            // history, but we don't need or desire it
            // cluttering up the buffer.
            $this->readTo($this->_prompt);
            $this->clearBuffer();
        }

        //$this->setPrompt("MYCUSTOMSSHPROMPT>");
        //$this->exec('prompt MYCUSTOMSSHPROMPT$G');
    }

    /**
     * Reads characters from the shell and adds them to command buffer.
     * Handles telnet control characters. Stops when prompt is ecountered.
     *
     * @param string $prompt
     *
     * @throws exception
     *
     * @return bool
     */
    private function readTo($prompt = null)
    {
        // What Prompt do we read to?
        if ($prompt != null) {
            $thisPrompt = $prompt;
        } else {
            $thisPrompt = $this->_prompt;
        }

        // If we don't have a connection, throw an exception
        if (!$this->_connection) {
            throw new Exception('SSH connection closed');
        }

        // Clear the buffer
        $this->clearBuffer();

        do {
            // get a character
            $c = fgetc($this->_shell);

            // if there isn't one, we have an issue
            if ($c === false) {
                throw new Exception("Couldn't find the requested : '".$thisPrompt."', it was not in the data returned from server : '".$this->_buffer."'");
            }

            // Interpreted As Command?
            if ($c == $this->_IAC) {
                if ($this->negotiateTelnetOptions()) {
                    continue;
                }
            }

            // append current char to the buffer and to the history.
            $this->_buffer .= $c;
            $this->_history .= $c;

            if ($this->_debug) {
                file_put_contents($this->_debugLog, $c, FILE_APPEND);
            }

            // Have we encountered the prompt? Break out of the loop
            if ((substr($this->_buffer, strlen($this->_buffer) - strlen($thisPrompt))) == $thisPrompt) {
                return self::SSH_OK;
            }
        } while ($c != $this->_NULL || $c != $this->_DC1);
    }

    /*
    * Get the full History of the shell session.
    *
    */
    public function getHistory()
    {
        return $this->_history;
    }

    /**
     * Telnet control character magic.
     *
     * @param string $command Character to check
     *
     * @return bool
     */
    private function negotiateTelnetOptions()
    {
        $c = fgetc();

        if ($c != $this->_IAC) {
            if (($c == $this->_DO) || ($c == $this->_DONT)) {
                $opt = fgetc();
                fwrite($this->socket, $this->_IAC.$this->_WONT.$opt);
            } elseif (($c == $this->_WILL) || ($c == $this->_WONT)) {
                $opt = fgetc();
                fwrite($this->socket, $this->_IAC.$this->_DONT.$opt);
            } else {
                throw new Exception('Error: unknown control character '.ord($c));
            }
        } else {
            throw new Exception('Error: Something Wicked Happened');
        }

        return self::SSH_OK;
    }

    /**
     * Write command to a socket.
     *
     * @param string $buffer     Stuff to write to socket
     * @param bool   $addNewLine Default true, adds newline to the command
     *
     * @throws exception
     *
     * @return bool
     */
    public function write($buffer, $addNewLine = true)
    {

        // If we don't have a shell, throw an exception
        if (!$this->_shell) {
            throw new Exception('FATAL: SSH connection closed');
        }

        // Clear buffer from last command
        $this->clearBuffer();

        // If we are adding newlines, then do so.
        if ($addNewLine == true) {
            $buffer .= PHP_EOL;
        }

        // write to the shell, exception if there is an error.
        if (!fwrite($this->_shell, $buffer) < 0) {
            throw new Exception('ERROR: Error writing to shell');
        }

        // Take a quick nap.
        usleep(3500);

        return self::SSH_OK;
    }

    /**
     * Executes a command and returns the results.
     *
     * @param string $cmd Command we want to execute.
     *
     * @return string Error Message | Command Results
     */
    public function exec($cmd)
    {
        try {
            echo "{trying $cmd}}\n";
            $this->write($cmd);
            $this->readTo($this->_prompt);
            $buf = explode("\n", $this->_buffer);
            //cut first line (is the last command)
            $buf[0] = '';
            // cut last line (is always prompt)
            $buf[count($buf) - 1] = '';
            $buf = implode("\n", $buf);

            return trim($buf);
        } catch (Exception $e) {
            return $e->getMessage();
        }
    }

    /**
     * Returns the content of the command buffer.
     *
     * @return string Content of the command buffer
     */
    public function getBuffer()
    {
        $this->readTo($this->_prompt);

        return $this->_buffer;
    }

    public function uploadFile($localFile, $remoteFile)
    {
        return ssh2_scp_send($this->_connection, $localFile, $remoteFile);
    }

    public function deleteFile($remoteFile)
    {
        if (!$this->_sftp) {
            $this->_sftp = @ssh2_sftp($this->_connection);
            if (!$this->_sftp) {
                throw new Exception('Could not establish sftp connection');
            }
        }

        return ssh2_sftp_unlink($this->_sftp, $remoteFile);
    }
}
