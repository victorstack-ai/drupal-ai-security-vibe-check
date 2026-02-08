<?php

namespace Drupal\Tests\ai_security_vibe_check\Unit;

use Drupal\ai_security_vibe_check\VibeAuditService;
use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\State\StateInterface;
use Drupal\Tests\UnitTestCase;

/**
 * Tests the VibeAuditService.
 *
 * @group ai_security_vibe_check
 */
class VibeAuditServiceTest extends UnitTestCase {

  /**
   * Tests the config check.
   */
  public function testCheckConfigForSecrets() {
    $config_factory = $this->createMock(ConfigFactoryInterface::class);
    $state = $this->createMock(StateInterface::class);

    $config_factory->method('listAll')->willReturn(['openai.settings']);
    
    $config = $this->createMock(Config::class);
    $config->method('getRawData')->willReturn([
      'api_key' => 'sk-12345678901234567890123456789012',
    ]);
    
    $config_factory->method('get')->with('openai.settings')->willReturn($config);

    $service = new VibeAuditService($config_factory, $state);
    $findings = $service->performAudit();

    $this->assertNotEmpty($findings);
    $this->assertEquals('secret_in_config', $findings[0]['type']);
    $this->assertStringContainsString('openai', $findings[0]['message']);
  }

}
