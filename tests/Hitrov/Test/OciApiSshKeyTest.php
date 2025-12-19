<?php

namespace Hitrov\Test;

use Hitrov\OciApi;
use Hitrov\Test\Traits\DefaultConfig;
use PHPUnit\Framework\TestCase;

class OciApiSshKeyTest extends TestCase
{
    use DefaultConfig;

    /**
     * Test that createInstance works with null SSH key
     */
    public function testCreateInstanceWithNullSshKey(): void
    {
        $mock = $this->getMockBuilder(OciApi::class)
            ->onlyMethods(['call'])
            ->getMock();

        // Expect that call is made with metadata not containing ssh_authorized_keys
        $mock->expects($this->once())
            ->method('call')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->callback(function ($body) {
                    $decoded = json_decode($body, true);
                    // Verify that metadata is empty or doesn't contain ssh_authorized_keys
                    return empty($decoded['metadata']) || !isset($decoded['metadata']['ssh_authorized_keys']);
                })
            )
            ->willReturn([]);

        $mock->createInstance($this->getDefaultConfig(), 'VM.Standard.A1.Flex', null, 'ad-1');
    }

    /**
     * Test that createInstance works with empty string SSH key
     */
    public function testCreateInstanceWithEmptyStringSshKey(): void
    {
        $mock = $this->getMockBuilder(OciApi::class)
            ->onlyMethods(['call'])
            ->getMock();

        // Expect that call is made with metadata not containing ssh_authorized_keys
        $mock->expects($this->once())
            ->method('call')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->callback(function ($body) {
                    $decoded = json_decode($body, true);
                    // Verify that metadata is empty or doesn't contain ssh_authorized_keys
                    return empty($decoded['metadata']) || !isset($decoded['metadata']['ssh_authorized_keys']);
                })
            )
            ->willReturn([]);

        $mock->createInstance($this->getDefaultConfig(), 'VM.Standard.A1.Flex', '', 'ad-1');
    }

    /**
     * Test that createInstance works with valid SSH key
     */
    public function testCreateInstanceWithValidSshKey(): void
    {
        $sshKey = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGJeJvUx8YNhzuPzLKTvXJFMfLbPVvLfYh1K+QI0Q4F test@example.com';
        
        $mock = $this->getMockBuilder(OciApi::class)
            ->onlyMethods(['call'])
            ->getMock();

        // Expect that call is made with metadata containing ssh_authorized_keys
        $mock->expects($this->once())
            ->method('call')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->callback(function ($body) use ($sshKey) {
                    $decoded = json_decode($body, true);
                    // Verify that metadata contains the SSH key
                    return isset($decoded['metadata']['ssh_authorized_keys']) 
                        && $decoded['metadata']['ssh_authorized_keys'] === $sshKey;
                })
            )
            ->willReturn([]);

        $mock->createInstance($this->getDefaultConfig(), 'VM.Standard.A1.Flex', $sshKey, 'ad-1');
    }

    /**
     * Test that createInstance throws exception for invalid SSH key format
     */
    public function testCreateInstanceWithInvalidSshKeyFormat(): void
    {
        $api = new OciApi();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid SSH public key format');

        $api->createInstance($this->getDefaultConfig(), 'VM.Standard.A1.Flex', 'not-a-valid-ssh-key', 'ad-1');
    }

    /**
     * Test that createInstance throws exception for SSH key not starting with ssh-
     */
    public function testCreateInstanceWithSshKeyNotStartingWithSshPrefix(): void
    {
        $api = new OciApi();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid SSH public key format');

        $api->createInstance($this->getDefaultConfig(), 'VM.Standard.A1.Flex', 'rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ test@example.com', 'ad-1');
    }

    /**
     * Test that createInstance handles whitespace-only SSH key as null
     */
    public function testCreateInstanceWithWhitespaceOnlySshKey(): void
    {
        $mock = $this->getMockBuilder(OciApi::class)
            ->onlyMethods(['call'])
            ->getMock();

        // Expect that call is made with metadata not containing ssh_authorized_keys
        $mock->expects($this->once())
            ->method('call')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->callback(function ($body) {
                    $decoded = json_decode($body, true);
                    // Verify that metadata is empty or doesn't contain ssh_authorized_keys
                    return empty($decoded['metadata']) || !isset($decoded['metadata']['ssh_authorized_keys']);
                })
            )
            ->willReturn([]);

        $mock->createInstance($this->getDefaultConfig(), 'VM.Standard.A1.Flex', '   ', 'ad-1');
    }

    /**
     * Test that createInstance works with ssh-ed25519 key format
     */
    public function testCreateInstanceWithEd25519SshKey(): void
    {
        $sshKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com';
        
        $mock = $this->getMockBuilder(OciApi::class)
            ->onlyMethods(['call'])
            ->getMock();

        // Expect that call is made with metadata containing ssh_authorized_keys
        $mock->expects($this->once())
            ->method('call')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->callback(function ($body) use ($sshKey) {
                    $decoded = json_decode($body, true);
                    // Verify that metadata contains the SSH key
                    return isset($decoded['metadata']['ssh_authorized_keys']) 
                        && $decoded['metadata']['ssh_authorized_keys'] === $sshKey;
                })
            )
            ->willReturn([]);

        $mock->createInstance($this->getDefaultConfig(), 'VM.Standard.A1.Flex', $sshKey, 'ad-1');
    }

    /**
     * Test that createInstance trims SSH key with leading/trailing spaces
     */
    public function testCreateInstanceTrimsSshKey(): void
    {
        $sshKeyWithSpaces = '  ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGJeJvUx8YNhzuPzLKTvXJFMfLbPVvLfYh1K+QI0Q4F test@example.com  ';
        $trimmedSshKey = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGJeJvUx8YNhzuPzLKTvXJFMfLbPVvLfYh1K+QI0Q4F test@example.com';
        
        $mock = $this->getMockBuilder(OciApi::class)
            ->onlyMethods(['call'])
            ->getMock();

        // Expect that call is made with metadata containing the trimmed SSH key
        $mock->expects($this->once())
            ->method('call')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->callback(function ($body) use ($trimmedSshKey) {
                    $decoded = json_decode($body, true);
                    // Verify that metadata contains the trimmed SSH key
                    return isset($decoded['metadata']['ssh_authorized_keys']) 
                        && $decoded['metadata']['ssh_authorized_keys'] === $trimmedSshKey;
                })
            )
            ->willReturn([]);

        $mock->createInstance($this->getDefaultConfig(), 'VM.Standard.A1.Flex', $sshKeyWithSpaces, 'ad-1');
    }
}
