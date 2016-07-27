<?php

namespace Eusebiu\GameCenterIdentity;

class Verifier
{
    const CERT_DOWNLOAD_ERR = 1;
    const CERT_PUB_KEY_ERR = 2;
    const SIGNATURE_INCORRECT = 3;
    const SIGNATURE_ERR = 3;

    protected $error = 0;
    protected $signature;
    protected $certificate;

    /**
     * Create a new instance.
     *
     * @param  string $signature Binary string.
     * @param  string $certificate Certificate or URL.
     * @return void
     */
    public function __construct($signature, $certificate)
    {
        $this->signature = $signature;
        $this->certificate = $certificate;
    }

    /**
     * Verifiy the given data.
     *
     * @param  string $playerId
     * @param  string $bundleId
     * @param  int    $timestamp
     * @param  string $salt Binary string.
     * @return bool
     */
    public function verify($playerId, $bundleId, $timestamp, $salt)
    {
        if (filter_var($this->certificate, FILTER_VALIDATE_URL) !== false) {
            $this->certificate = file_get_contents($this->certificate);

            if ($this->certificate === false) {
                $this->error = static::CERT_DOWNLOAD_ERR;
                return false;
            }
        }

        if (($pubKeyId = $this->pubKey()) === false) {
            $this->error = static::CERT_PUB_KEY_ERR;
            return false;
        }

        $data = $playerId . $bundleId . $this->toBigEndian($timestamp) . $salt;

        $result = openssl_verify($data, $this->signature, $pubKeyId, OPENSSL_ALGO_SHA256);

        if ($result === 1) {
            return true;
        }

        if ($result === 0) {
            $this->error = static::SIGNATURE_INCORRECT;
        } else {
            $this->error = static::SIGNATURE_ERR;
        }

        return false;
    }

    protected function pubKey()
    {
        $pem = $this->cer2pem($this->certificate);

        return openssl_pkey_get_public($pem);
    }

    protected function downloadCert($url)
    {
        return file_get_contents($url);
    }

    protected function cer2pem($data)
    {
       $pem = chunk_split(base64_encode($data), 64, "\n");

       return "-----BEGIN CERTIFICATE-----\n{$pem}-----END CERTIFICATE-----\n";
    }

    protected function toBigEndian($timestamp)
    {
        if (PHP_INT_SIZE === 4) {
            $hex = '';

            do {
                $last = bcmod($timestamp, 16);
                $hex = dechex($last) . $hex;
                $timestamp = bcdiv(bcsub($timestamp, $last), 16);
            } while ($timestamp > 0);

            return hex2bin(str_pad($hex, 16, '0', STR_PAD_LEFT));
        }

        $highMap = 0xffffffff00000000;
        $lowMap = 0x00000000ffffffff;
        $higher = ($timestamp & $highMap) >>32;
        $lower = $timestamp & $lowMap;

        return pack('N2', $higher, $lower);
    }

    /**
     * Get the error code.
     *
     * @return int
     */
    public function getError()
    {
        return $this->error;
    }
}
