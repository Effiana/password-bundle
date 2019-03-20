<?php
/**
 * This file is part of the Effiana package.
 *
 * (c) Effiana, LTD
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @author Dominik Labudzinski <dominik@labudzinski.com>
 */
declare(strict_types=1);

namespace Effiana\PasswordBundle;

use Monolog\Handler\MissingExtensionException;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;

/**
 * Class PasswordEncoder.
 */
class PasswordEncoder implements PasswordEncoderInterface
{
    const HASH_ALGORITHM = 'sha512';

    /**
     * @var string
     */
    private $_salt;

    /**
     * @var array
     */
    private $options;

    /**
     * Constructor.
     *
     * @param string $salt
     *
     * @throws MissingExtensionException
     */
    public function __construct($salt = null)
    {
        if (null === $salt) {
            throw new InvalidArgumentException('Salt can not be empty.');
        }

        if (false === \ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_is_available()) {
            throw new MissingExtensionException('AES256GCM is not supported by the processor');
        }
        $this->_salt = $salt;

        $this->options = [
            'memory_cost' => 1<<17,
            'time_cost'   => 5,
            'threads'     => 2,
        ];
    }

    /**
     * Encodes the raw password.
     *
     * @param string $raw  The password to encode
     * @param string $salt The salt
     *
     * @return string The encoded password
     *
     * @throws \SodiumException
     *
     */
    public function encodePassword($raw, $salt): string
    {
        $hash = hash(self::HASH_ALGORITHM, $raw);
        $hash = sprintf('pass_%s_%s', $hash, $salt);
        $hash = password_hash($hash, PASSWORD_ARGON2I, $this->options);

        $key = hash(self::HASH_ALGORITHM, $this->_salt);
        $aad = hash(self::HASH_ALGORITHM, hash('whirlpool', $this->_salt));

        /**
         * Attempting to encrypt using AES256GCM.
         */
        $nonce = substr($key, 0, \ParagonIE_Sodium_Compat::CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        $key = substr($key, 0, \ParagonIE_Sodium_Compat::CRYPTO_AEAD_AES256GCM_KEYBYTES);
        $hash = \ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_encrypt(
            $hash,
            $aad,
            $nonce,
            $key
        );
        $encrypted = base64_encode($hash);

        /*
         * Clear memory for variables
         */
        \ParagonIE_Sodium_Compat::memzero($hash);
        \ParagonIE_Sodium_Compat::memzero($key);
        \ParagonIE_Sodium_Compat::memzero($nonce);
        \ParagonIE_Sodium_Compat::memzero($aad);

        return $encrypted;
    }

    /**
     * Checks a raw password against an encoded password.
     *
     * @param string $encrypted
     * @param string $raw
     * @param string $salt
     *
     * @return bool
     *
     * @throws \SodiumException
     */
    public function isPasswordValid($encrypted, $raw, $salt): bool
    {
        $hash = hash(self::HASH_ALGORITHM, $raw);
        $hash = sprintf('pass_%s_%s', $hash, $salt);

        $key = hash(self::HASH_ALGORITHM, $this->_salt);
        $aad = hash(self::HASH_ALGORITHM, hash('whirlpool', $this->_salt));

        $encrypted = base64_decode($encrypted);

        /**
         * Attempting to decrypt using AES256GCM.
         */
        $nonce = substr($key, 0, \ParagonIE_Sodium_Compat::CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        $key = substr($key, 0, \ParagonIE_Sodium_Compat::CRYPTO_AEAD_AES256GCM_KEYBYTES);
        $decrypted = \ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_decrypt(
            $encrypted,
            $aad,
            $nonce,
            $key
        );

        /*
         * Clear memory for variables
         */
        \ParagonIE_Sodium_Compat::memzero($encrypted);
        \ParagonIE_Sodium_Compat::memzero($key);
        \ParagonIE_Sodium_Compat::memzero($nonce);
        \ParagonIE_Sodium_Compat::memzero($aad);

        if (false === $decrypted) {
            /*
             * Clear memory for variables
             */
            \ParagonIE_Sodium_Compat::memzero($raw);
            throw new BadCredentialsException('Sodium: Bad ciphertext');
        }
        if (false === password_verify($hash, $encrypted)) {
            /*
             * Clear memory for variables
             */
            \ParagonIE_Sodium_Compat::memzero($raw);
            \ParagonIE_Sodium_Compat::memzero($decrypted);
            throw new BadCredentialsException('The presented password is invalid.');
        }

        /*
         * Clear memory for variables
         */
        \ParagonIE_Sodium_Compat::memzero($raw);
        \ParagonIE_Sodium_Compat::memzero($decrypted);

        return true;
    }
}