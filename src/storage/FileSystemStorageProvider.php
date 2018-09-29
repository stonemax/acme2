<?php /** @noinspection PhpDocMissingThrowsInspection */

namespace stonemax\acme2\storage;

use stonemax\acme2\exceptions\StorageException;

class FileSystemStorageProvider extends StorageProvider
{

    const ACCOUNT_DIR = DIRECTORY_SEPARATOR . "account";
    const DOMAIN_DIR = DIRECTORY_SEPARATOR . "domains";

    private $baseDir;

    /**
     * FileSystemStorageProvider constructor.
     * @param $baseDir
     * @throws StorageException
     */
    public function __construct($baseDir)
    {
        $this->baseDir = $baseDir;
        if (
            !is_dir($baseDir) && (
                mkdir($baseDir, 0755, TRUE) === FALSE ||
                mkdir($baseDir . FileSystemStorageProvider::ACCOUNT_DIR, 0755, TRUE) === FALSE ||
                mkdir($baseDir . FileSystemStorageProvider::DOMAIN_DIR, 0755, TRUE) === FALSE
            )
        ) {
            throw new StorageException("create directory({$baseDir}) failed, please check the permission.");
        }
    }

    /**
     * @param $fileName
     * @return mixed
     */
    public function getAccountDataFileExists($fileName)
    {
        return is_file($this->baseDir . FileSystemStorageProvider::ACCOUNT_DIR . DIRECTORY_SEPARATOR . $fileName);
    }

    /**
     * @param string $fileName
     * @return string Data in file
     */
    public function getAccountDataFile($fileName)
    {
        return file_get_contents($this->baseDir . FileSystemStorageProvider::ACCOUNT_DIR . DIRECTORY_SEPARATOR . $fileName);
    }

    /**
     * @param $fileName
     * @param $content
     * @return bool
     */
    public function saveAccountDataFile($fileName, $content)
    {
        return file_put_contents($this->baseDir . FileSystemStorageProvider::ACCOUNT_DIR . DIRECTORY_SEPARATOR . $fileName, $content);
    }

    /**
     * @param $fileName
     * @return bool
     */
    public function deleteAccountDataFile($fileName)
    {
        return @unlink($this->baseDir . DIRECTORY_SEPARATOR . $fileName);
    }

    private function makeDomainAlgoDir($domain, $algo)
    {
        $dir = $this->baseDir . FileSystemStorageProvider::DOMAIN_DIR . DIRECTORY_SEPARATOR . $domain . DIRECTORY_SEPARATOR . $algo;
        if (!is_dir($dir) && !mkdir($dir, 0755, TRUE)) {
            throw new StorageException("create directory({$dir}) failed, please check the permission.");
        }
        return $dir;
    }

    /**
     * @param $domain
     * @param $algo
     * @param $fileName
     * @return mixed
     */
    public function getDomainDataFileExists($domain, $algo, $fileName)
    {
        return is_file($this->makeDomainAlgoDir($domain, $algo) . DIRECTORY_SEPARATOR . $fileName);
    }

    /**
     * @param string $domain
     * @param $algo
     * @param string $fileName
     * @return string Data in file
     */
    public function getDomainDataFile($domain, $algo, $fileName)
    {
        return file_get_contents($this->makeDomainAlgoDir($domain, $algo) . DIRECTORY_SEPARATOR . $fileName);
    }

    /**
     * @param $domain
     * @param $algo
     * @param $fileName
     * @param $content
     * @return bool
     */
    public function saveDomainDataFile($domain, $algo, $fileName, $content)
    {
        return file_put_contents($this->makeDomainAlgoDir($domain, $algo) . DIRECTORY_SEPARATOR . $fileName, $content);
    }

    /**
     * @param $domain
     * @param $algo
     * @param $fileName
     * @return bool
     */
    public function deleteDomainDataFile($domain, $algo, $fileName)
    {
        return @unlink($this->makeDomainAlgoDir($domain, $algo) . DIRECTORY_SEPARATOR . $fileName);
    }
}