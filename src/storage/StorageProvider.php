<?php

namespace stonemax\acme2\storage;

abstract class StorageProvider
{

    /**
     * @param $fileName
     * @return mixed
     */
    public abstract function getAccountDataFileExists($fileName);

    /**
     * @param string $fileName
     * @return string Data in file
     */
    public abstract function getAccountDataFile($fileName);

    /**
     * @param $fileName
     * @param $content
     * @return bool
     */
    public abstract function saveAccountDataFile($fileName, $content);

    /**
     * @param $fileName
     * @return bool
     */
    public abstract function deleteAccountDataFile($fileName);

    /**
     * @param $domain
     * @param $algo
     * @param $fileName
     * @return mixed
     */
    public abstract function getDomainDataFileExists($domain, $algo, $fileName);

    /**
     * @param string $domain
     * @param $algo
     * @param string $fileName
     * @return string Data in file
     */
    public abstract function getDomainDataFile($domain, $algo, $fileName);

    /**
     * @param $domain
     * @param $algo
     * @param $fileName
     * @param $content
     * @return bool
     */
    public abstract function saveDomainDataFile($domain, $algo, $fileName, $content);

    /**
     * @param $domain
     * @param $algo
     * @param $fileName
     * @return bool
     */
    public abstract function deleteDomainDataFile($domain, $algo, $fileName);


}