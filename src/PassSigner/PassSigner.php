<?php
namespace PassSigner;

// Common CN for Apple Certificate
if (!defined('APPLE_CERTIFICATE_CN')) {
    define(
        'APPLE_CERTIFICATE_CN',
        "Apple Worldwide Developer Relations Certification Authority"
    );
}

class PassSigner
{
    /**
     * Signs and packs a PKPass directory
     * 
     * @param  string   $passPath      The starting pass directory
     * @param  string   $certPath      Path to the developer's certificate in .pem format
     * @param  string   $certPassword  Password for the certificate
     * @param  string   $outputPath    Path of the .pkpass output file
     * @param  boolean  $zip           Create ZIP/PKPass package
     * @return void
     * @throws exception
     */
    public static function signPass($passPath, $certPath, $certPassword, $outputPath, $zip = true)
    {
        self::checkAppleCertificate();
        
        // Validate that requested contents are not a signed
        // and expanded pass archive.
        self::validateDirectoryAsUnsignedRawPass($passPath);
    
        // Get a temporary place to stash the pass contents
        $tempDir = sys_get_temp_dir() . '/' . pathinfo($passPath, PATHINFO_BASENAME);
        
        // Try to delete if already exists
        if (file_exists($tempDir) && is_dir($tempDir)) {
            if (!self::rrmdir($tempDir)) {
                throw new \Exception("Unable to remove temporary directory '$tempDir'", 502);
            }
        }

        // Make a copy of the pass contents to the temporary folder
        self::rcopy($passPath, $tempDir);
    
        // Clean out the unneeded .DS_Store files
        if ($junks = glob($tempDir . '*/.DS_Store')) {
            foreach ($junks as $j) {
                unlink($j);
            }
        }
    
        // Build the json manifest
        $manifestData = array();
        $files = new \DirectoryIterator($passPath);
        foreach ($files as $file) {

            // Ignore unwanted files
            if (in_array($file, array('.', '..', '.DS_Store'))) {
                continue;
            }
            
            $key = trim(str_replace($passPath, '', $file->getPathName()), '/');

            $manifestData[$key] = sha1_file($file->getPathName());
        }
        
        // Write the manifest.json file
        $manifestPath = $tempDir . '/manifest.json';
        if (!file_put_contents($manifestPath, json_encode($manifestData))) {
            throw new \Exception("Unable to write file '{$manifestPath}'", 511);
        }
        
        // Sign the manifest
        $signaturePath = $tempDir . '/signature';
        
        // We cannot use openssl_pkcs7_sign() because the binary output feature
        // doesn't work and is not valid for Apple verify script

        // Sign using openssl shell command
        $signCommand = sprintf(
            'openssl smime -binary -sign -certfile "%s" -signer "%s" -inkey "%s" -in "%s" -out "%s" -outform DER -passin pass:%s',
            APPLE_CERTIFICATE,
            $certPath,
            $certPath,
            $manifestPath,
            $signaturePath,
            $certPassword
        );

        $signResult = false;
        $signOut = array(); // needed but unused
        exec($signCommand, $signOut, $signResult);
        unset($signOut);
        
        if (0 !== $signResult) {
            throw new \Exception("Unable to sign manifest file '{$manifestPath}'", 511);
        }
    
        // Package pass
        if ($zip === true) {
            $zip = new \ZipArchive();
            $zipFile = $outputPath;
            if ($zip->open($zipFile, \ZipArchive::CREATE) != true) {
                throw new \Exception("Unable open archive '$zipFile'");
            }

            $files = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($tempDir)
            );
            $excludes = array('.DS_Store', '.', '..');
            foreach ($files as $file) {
                if (in_array(basename($file), $excludes)) {
                    continue;
                }
                if (is_dir($file)) {
                    $zip->addEmptyDir(str_replace("$tempDir/", '', "$file/"));
                } elseif (is_file($file)) {
                    $zip->addFromString(
                        str_replace("$tempDir/", '', $file),
                        file_get_contents($file)
                    );
                }
            }
        
            // Search for residual .DS_Store files
            $zip->deleteName('.DS_Store');
            $zip->close();

        } else {
            
            if (!mkdir($outputPath)) {
                throw new \Exception("Unable to create output directory '$outputPath'", 512);
            }

            // The output pass is a directory
            self::rcopy($tempDir, $outputPath);
            
        }
    
        // Clean up the temp directory
        if (!self::rrmdir($tempDir)) {
            throw new \Exception("Unable to cleanup temporary directory '$tempDir'", 502);
        }
        
    }
    
    /**
     * Verifies a .pkpass package signature
     * 
     * If the optional $certs array is passed, it is filled with the extracted
     * certificates
     *
     * @param  string   $verifyPath  The starting pass directory
     * @param  string   $certs       Array in which to store the certificates
     * @return  boolean
     * @throws exception
     */
    public static function verifyPassSignature($verifyPath, &$certs = array())
    {
        self::checkAppleCertificate();
        
        // Check that the pass file is readable
        if (!is_readable($verifyPath)) {
            throw new \Exception("Unable to access file {$verifyPath}", 501);
        }

        // Get a temporary place to unpack the pass
        $tempDir = sys_get_temp_dir() . '/' . pathinfo($verifyPath, PATHINFO_BASENAME);

        // Try to delete if already exists
        if (file_exists($tempDir) && is_dir($tempDir)) {
            if (!self::rrmdir($tempDir)) {
                throw new \Exception("Unable to remove temporary directory '$tempDir'", 502);
            }
        }

        if (!mkdir($tempDir)) {
            throw new \Exception("Unable to create temporary directory '$tempDir'", 503);
        }

        // Unzip the pass
        $zip = new \ZipArchive();
        if ($zip->open($verifyPath) === true) {
            if ($zip->extractTo($tempDir) === false) {
                $zip->close();
                throw new \Exception("Unable to extract archive {$verifyPath}", 504);
            }
            $zip->close();
        } else {
            throw new \Exception("Unable to open archive {$verifyPath} to {$tempDir}", 505);
        }
        
        $valid = false;
        
        // Perform validation of signature and manifest
        if (self::validateManifest($tempDir) && self::validateSignature($tempDir, $certs)) {
            $valid = true;
        }
        
        if (!self::rrmdir($tempDir)) {
            throw new \Exception("Unable to cleanup temporary directory '$tempDir'", 506);
        }
        return $valid;
    }
    
    /**
     * Recursive remove directory
     * 
     * @param  string  $dir  The directory to delete
     * @return boolean
     */
    public static function rrmdir($dir)
    {
        $files = array_diff(scandir($dir), array('.','..'));
        foreach ($files as $file) {
            (is_dir("$dir/$file")) ? self::rrmdir("$dir/$file") : unlink("$dir/$file");
        }
        return rmdir($dir);
    }
    
    /**
     * Recursive copy of files and directories
     * 
     * If the source is a directory and the destination does not exists
     * it is created, else the contents of the source are copied to the 
     * destination directory
     *
     * @param  string  $source  Source file/directory path
     * @param  string  $dest    Destination file/directory path
     * @return boolean
     */
    public static function rcopy($source, $dest)
    {
        if (is_dir($source)) {
            if (!is_dir($dest)) {
                if (!mkdir($dest)) {
                    return false;
                }
            }
            $dir_handle=opendir($source);
            while ($file=readdir($dir_handle)) {
                if ($file!="." && $file!="..") {
                    if (is_dir($source."/".$file)) {
                        self::rcopy($source."/".$file, $dest."/".$file);
                    } else {
                        copy($source."/".$file, $dest."/".$file);
                    }
                }
            }
        } else {
            copy($source, $dest);
        }
        return true;
    }

    /**
     * Validates a manifest.json file
     * 
     * @param  $dir  The directory containing the manifest and pass files
     * @return boolean
     * @throws \Exception
     */
    protected static function validateManifest($dir)
    {
        $valid = true;
        
        $manifestPath = $dir . '/manifest.json';
        $manifestData = json_decode(file_get_contents($manifestPath), true);
        if (json_last_error() != JSON_ERROR_NONE) {
            throw new \Exception("Error parsing JSON manifest file");
        }

        $manifestCount = count($manifestData);
        
        $files = new \DirectoryIterator($dir);
        foreach ($files as $file) {
            
            // Ignore unwanted files
            if (in_array($file, array('.', '..', '.DS_Store', 'manifest.json', 'signature'))) {
                continue;
            }
            
            // Check that each file is present in the manifest
            if (!array_key_exists((string) $file, $manifestData)) {
                throw new \Exception(sprintf("No entry in manifest for file %s", $file), 506);
            }

            // Check SHA1 hash for each file
            $hash = sha1_file($file->getPathname());
            if ($hash === false || $hash !== $manifestData[(string) $file]) {
                throw new \Exception(
                    sprintf(
                        "For file %s, manifest's listed SHA1 hash %s doesn't match computed hash, %s",
                        $file,
                        $manifestData[(string) $file],
                        $hash
                    ),
                    507
                );
            }
            
            $manifestCount--;
            
            if (is_link($file->getPathname())) {
                throw new \Exception(sprintf("Card contains a symlink, %s, which is illegal", $file), 508);
            }
        }
        
        if ($valid && $manifestCount) {
            throw new \Exception("Card is missing files listed in the manifest", 509);
        }
        
        return $valid;
    }

    /**
     * Validates a signature
     * 
     * If the optional $certs array is passed, it is filled with the extracted
     * certificates
     *
     * @param  string   $dir    The directory containing the manifest and signature files
     * @param  string   $certs  Array in which to store the certificates
     * @param  boolean
     * @throws \Exception
     */
    protected static function validateSignature($dir, &$certs = array())
    {
        $valid = false;
        $manifestPath = $dir . '/manifest.json';
        $signaturePath = $dir . '/signature';
        
        // First verify the signed content without certificate control
        $verifyCommand = sprintf(
            'openssl smime -verify -binary -inform DER -in "%s" -content "%s" -noverify 2> /dev/null',
            $signaturePath,
            $manifestPath
        );
        
        $verifyResult = false;
        $verifyOut = array(); // needed but unused
        exec($verifyCommand, $verifyOut, $verifyResult);
        unset($verifyOut);
        
        if (0 !== $verifyResult) {
            throw new \Exception("Error validating signature", 513);
        }
        
        // Extract certificates from the signature
        $exportCommand = sprintf(
            'openssl smime -pk7out -in "%s" -content "%s" -inform DER -outform PEM',
            $signaturePath,
            $manifestPath
        );
    
        if (!$pemData = shell_exec($exportCommand)) {
            throw new \Exception("Error extracting certificates", 514);
        }

        $certs = self::parseCertificates($pemData);
        $foundWWDRCert = false;
        for ($i = 0; $i < count($certs); $i++) {
            $commonName = $certs[$i]['subject']['CN'];

            if ($commonName == APPLE_CERTIFICATE_CN) {
                $foundWWDRCert = true;
            }
        }

        if ($foundWWDRCert) {
            $valid = true;
        } else {
            throw new \Exception(
                "The Apple WWDR Intermediate Certificate must be included in the signature.\n".
                "https://developer.apple.com/certificationauthority/AppleWWDRCA.cer\n",
                515
            );
        }

        return $valid;
    }
    
    /**
     * Checks that the given directory is not an expanded pass
     * 
     * @param  string   $path  The raw pass directory to check
     * @param  boolean  $forceClean  Clean the directory before validation
     * @return void
     * @throws \Exception
     */
    protected static function validateDirectoryAsUnsignedRawPass($path, $forceClean = false)
    {
        if ($forceClean) {
            self::forceCleanRawPass($path);
        }
        
        if (file_exists($path . '/manifest.json') || file_exists($path . '/signature')) {
            throw new \Exception(
                "'$path' contains pass signing artificats that need to be removed before signing.",
                510
            );
        }
        
    }
    
    /**
     * Removes manifest and signature from a raw pass directory
     * 
     * @param  string   $path  The raw pass directory to clean
     * @return void
     */
    protected static function forceCleanRawPass($path)
    {
        
        //echo "Force cleaning the raw pass directory.\n";
        if (file_exists($path . '/manifest.json')) {
            unlink($path . '/manifest.json');
        }

        if (file_exists($path . '/signature')) {
            unlink($path . '/signature');
        }
    }
    
    /**
     * Checks that the Apple CA Certificate is available and readable
     * @return void
     * @throws exception
     */
    protected static function checkAppleCertificate()
    {
        if (!defined('APPLE_CERTIFICATE')) {
            throw new \Exception("The location of Apple WWDRCA certificate is not defined", 600);
        }
        if (!is_readable(APPLE_CERTIFICATE)) {
            throw new \Exception(
                sprintf(
                    "The Apple WWDRCA certificate file '%s' does not exists",
                    APPLE_CERTIFICATE
                ),
                602
            );
        }
    }

    /**
     * Extract certificates from a PEM file or string
     *
     * Please Note: the openssl shell command must be available on the system
     *  
     * @param  string  $input  Path to .pem file or PEM content
     * @return mixed   Array of certificates or FALSE on error
     */
    protected static function parseCertificates($input)
    {

        // Input is a file: execute openssl directly on the file
        // Errors are silenced: if the PEM content is passed can trigger the
        // sys error 'file name too long'
        if (@is_file($input) && is_readable($input)) {

            $command = sprintf('openssl pkcs7 -in "%s" -noout -print_certs', $input);
        
            $data = shell_exec($command);

        } elseif (is_string($input) && !empty($input)) {

            // Input is the content of the certificate, pass it to openssl via STDIN

            // Spawn process
            $process = proc_open(
                'openssl pkcs7 -noout -print_certs',
                array(
                    0 => array('pipe', 'r'), // Intercept STDIN
                    1 => array('pipe', 'w'), // Intercept STDOUT
                    2 => array('pipe', 'w'), // Intercept STDERR, prevent out on
                                             // screen or browser
                ),
                $pipes // Will contain the handles for our streams
            );
        
            if (is_resource($process)) {
            
                // Write our data to STDIN
                fwrite($pipes[0], $input);
                fclose($pipes[0]);
            
                // Collect process output from STDOUT
                $data = stream_get_contents($pipes[1]);
                fclose($pipes[1]);
            
                // Close and get return value
                $ret = proc_close($process);
            
                // Go ahead only if successful
                if ($ret !== 0) {
                     return false;
                }
            }
        }
    
        // Parse the command output data
        if (!empty($data) && is_string($data)) {
        
            // Each cert string is separated by 2 newlines
            $items = explode("\n\n", trim($data));
        
            foreach ($items as $item) {
            
                // Each section of the certificate is on a new line
                $sections = explode("\n", $item);
            
                // Parsing sections, each section is like:
                // section=/Key1=Value1/KeyN=ValueN
                foreach ($sections as $section) {
                    if (preg_match('/^subject=(.*)$/', $section, $matches)) {
                        if (!empty($matches[1])) {
                            $subject = $matches[1];
                            unset($matches);
                        
                            // Extract keys and values
                            $subject = explode('/', trim($subject, '/'));
                            foreach ($subject as $si) {
                            
                                // Compute an associative array for the section
                                $si = explode('=', $si);
                                $s[$si[0]] = $si[1];
                            }
                        
                            // Replace the original section content
                            // and clean temporary data
                            $subject = $s;
                            unset($si, $s);
                        }
                    }
                
                    // Same process for issuer too...
                    if (preg_match('/^issuer=(.*)$/', $section, $matches)) {
                        if (!empty($matches[1])) {
                            $issuer = $matches[1];
                            unset($matches);
                            $issuer = explode('/', trim($issuer, '/'));
                            foreach ($issuer as $ii) {
                            
                                // Compute an associative array for the section
                                $ii = explode('=', $ii);
                                $is[$ii[0]] = $ii[1];
                            }
                        
                            // Replace the original section content
                            // and clean temporary data
                            $issuer = $is;
                            unset($ii, $is);
                        }
                    }
                }
            
                $cert = array();
            
                foreach (array('subject', 'issuer') as $key) {
                    if (!empty($$key)) {
                        $cert[$key] = $$key;
                    }
                }
            
                $certs[] = $cert;
            }
        
            if (!empty($certs)) {
                return $certs;
            }
        }
    
        return false;
    }
}
