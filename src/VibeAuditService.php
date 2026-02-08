<?php

namespace Drupal\ai_security_vibe_check;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\State\StateInterface;

/**
 * Service to audit AI security risks.
 */
class VibeAuditService {

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The state service.
   *
   * @var \Drupal\Core\State\StateInterface
   */
  protected $state;

  /**
   * The app root.
   *
   * @var string
   */
  protected $appRoot;

  /**
   * Constructs a VibeAuditService object.
   */
  public function __construct(ConfigFactoryInterface $config_factory, StateInterface $state, string $app_root) {
    $this->configFactory = $config_factory;
    $this->state = $state;
    $this->appRoot = $app_root;
  }

  /**
   * Performs the audit.
   *
   * @return array
   *   An array of audit findings.
   */
  public function performAudit(): array {
    $findings = [];
    $findings = array_merge($findings, $this->checkConfigForSecrets());
    $findings = array_merge($findings, $this->checkPublicFiles());
    return $findings;
  }

  /**
   * Checks configuration for potential secrets.
   */
  protected function checkConfigForSecrets(): array {
    $findings = [];
    $config_names = $this->configFactory->listAll();

    // Patterns for common AI API keys.
    $patterns = [
      'openai' => '/sk-[a-zA-Z0-9]{32,}/',
      'anthropic' => '/sk-ant-api03-[a-zA-Z0-9\-_]{32,}/',
      'gemini' => '/AIzaSy[a-zA-Z0-9\-_]{33}/',
    ];

    foreach ($config_names as $name) {
      $config = $this->configFactory->get($name);
      $data = $config->getRawData();
      $this->recursiveCheck($data, $name, $patterns, $findings);
    }

    return $findings;
  }

  /**
   * Recursively check config data for secrets.
   */
  protected function recursiveCheck($data, $name, $patterns, &$findings) {
    if (is_array($data)) {
      foreach ($data as $key => $value) {
        $this->recursiveCheck($value, $name . ':' . $key, $patterns, $findings);
      }
    }
    elseif (is_string($data)) {
      foreach ($patterns as $type => $pattern) {
        if (preg_match($pattern, $data)) {
          $findings[] = [
            'type' => 'secret_in_config',
            'severity' => 'critical',
            'message' => sprintf('Potential %s API key found in configuration: %s', $type, $name),
          ];
        }
      }
    }
  }

  /**
   * Checks for public files that shouldn't be there.
   */
  protected function checkPublicFiles(): array {
    $findings = [];
    $dangerous_files = ['.env', '.git', 'composer.lock.bak', 'web.config.bak'];

    foreach ($dangerous_files as $file) {
      if (file_exists($this->appRoot . '/' . $file)) {
        $findings[] = [
          'type' => 'dangerous_file',
          'severity' => 'high',
          'message' => sprintf('Dangerous file found in web root: %s', $file),
        ];
      }
    }

    return $findings;
  }

}
