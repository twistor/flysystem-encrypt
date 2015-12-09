<?php

namespace Twistor\Flysystem;

use League\Flysystem\AdapterInterface;
use League\Flysystem\Config;
use League\Flysystem\Util;
use League\Flysystem\Util\MimeType;
use Twistor\Flysystem\PassthroughAdapter;

/**
 * Encrypts/decrypts transparently for a Flysystem adapter.
 */
class EncryptAdapter extends PassthroughAdapter
{
    /**
     * Constructs an EncryptAdapter object.
     *
     * @param \League\Flysystem\AdapterInterface $adapter The adapter to encrypt.
     * @param string $key The encryption key.
     *
     * @throws \LogicException Thrown when the key is the wrong size.
     */
    public function __construct(AdapterInterface $adapter, $key)
    {
        if (Util::contentSize($key) !== \Crypto::KEY_BYTE_SIZE) {
            throw new \LogicException('The key is the wrong size.');
        }

        $this->key($key);
        parent::__construct($adapter);
    }

    /**
     * Provides key storage that won't leak during stack traces.
     *
     * @param string The key. This can only be set once.
     *
     * @return string The encryption key.
     */
    private function key($key = null) {
        static $key_storage = [];

        $object_id = spl_object_hash($this);

        if (! isset($key_storage[$object_id])) {
            $key_storage[$object_id] = $key;
        }

        return $key_storage[$object_id];
    }

    /**
     * @inheritdoc
     */
    public function getMetadata($path)
    {
        if (false === $metadata = $this->getAdapter()->getMetadata($path)) {
            return false;
        }

        unset($metadata['size']);
        unset($metadata['mimetype']);

        return $metadata;
    }

    /**
     * @inheritdoc
     */
    public function getMimetype($path)
    {
        $extension = pathinfo($path, PATHINFO_EXTENSION);
        $mimetype = MimeType::detectByFileExtension($extension) ?: 'text/plain';

        return compact('path', 'mimetype');
    }

    /**
     * @inheritdoc
     */
    public function getSize($path)
    {
        if (! $decrypted = $this->read($path)) {
            return false;
        }

        $size = Util::contentSize($decrypted['contents']);

        return compact('path', 'size');
    }

    /**
     * @inheritdoc
     */
    public function read($path)
    {
        if (! $result = $this->getAdapter()->read($path)) {
            return false;
        }

         $result['contents'] = $this->decryptString($result['contents']);

        return $result;
    }

    /**
     * @inheritdoc
     */
    public function readStream($path)
    {
        if (! $result = $this->getAdapter()->readStream($path)) {
            return false;
        }

        $result['stream'] = $this->decryptStream($result['stream']);

        return $result;
    }

    /**
     * @inheritdoc
     */
    public function update($path, $contents, Config $config)
    {
        $contents = $this->encryptString($contents);

        return $this->getAdapter()->update($path, $contents, $config);
    }

    /**
     * @inheritdoc
     */
    public function updateStream($path, $resource, Config $config)
    {
        if (false === $resource = $this->encryptStream($resource)) {
            return false;
        }

        return $this->getAdapter()->updateStream($path, $resource, $config);
    }

    /**
     * @inheritdoc
     */
    public function write($path, $contents, Config $config)
    {
        $contents = $this->encryptString($contents);

        return $this->getAdapter()->write($path, $contents, $config);
    }

    /**
     * @inheritdoc
     */
    public function writeStream($path, $resource, Config $config)
    {
        if (false === $resource = $this->encryptStream($resource)) {
            return false;
        }

        return $this->getAdapter()->writeStream($path, $resource, $config);
    }

    /**
     * Decrypts a string.
     *
     * @param string $contents The string to decrypt.
     *
     * @return string The decrypted string.
     */
    private function decryptString($contents)
    {
        return \Crypto::Decrypt($contents, $this->key());
    }

    /**
     * Decrypts a stream.
     *
     * @param string $contents The stream to decrypt.
     *
     * @return resource|false The decrypted stream or false on failure.
     */
    private function decryptStream($resource)
    {
        if (false === $contents = stream_get_contents($resource)) {
            return false;
        }

        $stream = fopen('php://memory', 'r+b');
        fwrite($stream, $this->decryptString($contents));
        rewind($stream);

        return $stream;
    }

    /**
     * Encrypts a string.
     *
     * @param string $contents The string to encrypt.
     *
     * @return string The encrypted string.
     */
    private function encryptString($contents)
    {
        return \Crypto::Encrypt($contents, $this->key());
    }

    /**
     * Encrypts a stream.
     *
     * @param string $contents The stream to encrypt.
     *
     * @return resource|false The encrypted stream or false on failure.
     */
    private function encryptStream($resource)
    {
        if (false === $contents = stream_get_contents($resource)) {
            return false;
        }

        $stream = fopen('php://memory', 'r+b');
        fwrite($stream, $this->encryptString($contents));
        rewind($stream);

        return $stream;
    }
}
