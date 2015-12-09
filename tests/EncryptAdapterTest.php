<?php

use League\Flysystem\Config;
use League\Flysystem\Memory\MemoryAdapter;
use Twistor\Flysystem\EncryptAdapter;

/**
 * @coversDefaultClass \Twistor\Flysystem\EncryptAdapter
 */
class EncryptAdapterTest  extends \PHPUnit_Framework_TestCase
{
    /**
     * The encrypt adapter.
     *
     * @var \Twistor\Flysystem\EncryptAdapter
     */
    protected $adapter;

    /**
     * The encryption key generated for the test.
     *
     * @var string
     */
    protected $key;

    /**
     * The memory adapter.
     *
     * @var \League\Flysystem\Memory\MemoryAdapter
     */
    protected $memory;

    /**
     * @inheritdoc
     */
    public function setUp()
    {
        $this->key = \Crypto::CreateNewRandomKey();
        $this->memory = new MemoryAdapter();
        $this->adapter = new EncryptAdapter($this->memory, $this->key);
        $this->adapter->write('test.png', 'file content', new Config());
    }

    /**
     * @covers ::__construct
     * @covers ::key
     *
     * @expectedException \LogicException
     */
    public function testConstruct()
    {
        new EncryptAdapter(new MemoryAdapter(), \Crypto::CreateNewRandomKey());
        new EncryptAdapter(new MemoryAdapter(), '123');
    }

    /**
     * @covers ::getMetadata
     */
    public function testGetMetadata()
    {
        $result = $this->adapter->getMetadata('test.png');
        $this->assertArrayNotHasKey('size', $result);
        $this->assertArrayNotHasKey('metadata', $result);
    }

    /**
     * @covers ::getMimetype
     */
    public function testGetMimetype()
    {
        $result = $this->adapter->getMimetype('test.png');
        $this->assertSame('image/png', $result['mimetype']);
    }

    /**
     * @covers ::getSize
     */
    public function testGetSize()
    {
        $result = $this->adapter->getSize('test.png');
        $this->assertSame(12, $result['size']);
    }

    /**
     * @covers ::read
     * @covers ::decryptString
     */
    public function testRead()
    {
        $result = $this->adapter->read('test.png');
        $this->assertSame('file content', $result['contents']);
    }

    /**
     * @covers ::readStream
     * @covers ::decryptStream
     */
    public function testReadStream()
    {
        $result = $this->adapter->readStream('test.png');
        $this->assertSame('file content', stream_get_contents($result['stream']));
    }

    /**
     * @covers ::update
     * @covers ::encryptString
     */
    public function testUpdate()
    {
        $result = $this->adapter->update('test.png', 'new file content', new Config());
        $this->assertSame('new file content', $this->decrypt($result['contents']));

        // Test that the adapter gets the encrypted content.
        $mem = $this->memory->read('test.png');
        $this->assertSame('new file content', $this->decrypt($mem['contents']));
    }

    /**
     * @covers ::updateStream
     * @covers ::encryptStream
     */
    public function testUpdateStream()
    {
        $stream = fopen('data:text/plain,newfilecontent', 'r+b');

        $this->adapter->updateStream('test.png', $stream, new Config());

        // Test that the adapter gets the encrypted content.
        $mem = $this->memory->read('test.png');
        $this->assertSame('newfilecontent', $this->decrypt($mem['contents']));
    }

    /**
     * @covers ::write
     */
    public function testWrite()
    {
        $result = $this->adapter->write('test.png', 'new file content', new Config());
        $this->assertSame('new file content', $this->decrypt($result['contents']));

        // Test that the adapter gets the encrypted content.
        $mem = $this->memory->read('test.png');
        $this->assertSame('new file content', $this->decrypt($mem['contents']));
    }

    /**
     * @covers ::writeStream
     */
    public function testWriteStream()
    {
        $stream = fopen('data:text/plain,newfilecontent', 'r+b');

        $this->adapter->writeStream('test.png', $stream, new Config());

        // Test that the adapter gets the encrypted content.
        $mem = $this->memory->read('test.png');
        $this->assertSame('newfilecontent', $this->decrypt($mem['contents']));
    }

    /**
     * Decrypts a string.
     *
     * @param string $contents The string to decrypt.
     *
     * @return string The decrypted string.
     */
    protected function decrypt($contents)
    {
        return \Crypto::Decrypt($contents, $this->key);
    }

    /**
     * Encrypts a string.
     *
     * @param string $contents The string to encrypt.
     *
     * @return string The encrypted string.
     */
    protected function encrypt($contents)
    {
        return \Crypto::Encrypt($contents, $this->key);
    }
}
