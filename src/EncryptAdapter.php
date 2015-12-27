<?php

namespace Twistor\Flysystem;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\File;
use Defuse\Crypto\Key;
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
    public function __construct(AdapterInterface $adapter, Key $key)
    {
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
        $resource = $this->encryptStream($resource);

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
        $resource = $this->encryptStream($resource);

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
        $resource = fopen('php://memory', 'r+b');
        File::writeBytes($resource, $contents);
        rewind($resource);

        return stream_get_contents($this->decryptStream($resource));
    }

    /**
     * Decrypts a stream.
     *
     * @param resource $resource The stream to decrypt.
     *
     * @return resource The decrypted stream.
     */
    private function decryptStream($resource)
    {
        $out = fopen('php://memory', 'r+b');

        File::decryptResource($resource, $out, $this->key());
        rewind($out);

        return $out;
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
        $resource = fopen('php://memory', 'r+b');
        File::writeBytes($resource, $contents);
        rewind($resource);

        return stream_get_contents($this->encryptStream($resource));
    }

    /**
     * Encrypts a stream.
     *
     * @param resource $resource The stream to encrypt.
     *
     * @return resource The encrypted stream.
     */
    private function encryptStream($resource)
    {

        $out = fopen('php://temp', 'r+b');

        File::encryptResource($resource, $out, $this->key());
        rewind($out);

        return $out;
    }
}
