<?php

namespace Drupal\ai_security_vibe_check\Commands;

use Drush\Commands\DrushCommands;
use Drupal\ai_security_vibe_check\VibeAuditService;

/**
 * Drush commands for AI Security Vibe Check.
 */
class VibeCheckCommands extends DrushCommands {

  /**
   * The audit service.
   *
   * @var \Drupal\ai_security_vibe_check\VibeAuditService
   */
  protected $auditService;

  /**
   * Constructs a VibeCheckCommands object.
   */
  public function __construct(VibeAuditService $audit_service) {
    parent::__construct();
    $this->auditService = $audit_service;
  }

  /**
   * Audits the Drupal site for AI-related security risks.
   *
   * @command ai:vibe-check
   * @aliases aivc
   * @usage drush ai:vibe-check
   */
  public function audit() {
    $this->output()->writeln('Running AI Security Vibe Check...');
    $findings = $this->auditService->performAudit();

    if (empty($findings)) {
      $this->logger()->success('No major AI security risks found. Vibe is safe!');
      return;
    }

    foreach ($findings as $finding) {
      $color = ($finding['severity'] === 'critical') ? 'red' : 'yellow';
      $this->output()->writeln(sprintf('<fg=%s>[%s]</> %s', $color, strtoupper($finding['severity']), $finding['message']));
    }

    $this->logger()->error(sprintf('Found %d security risks.', count($findings)));
  }

}
