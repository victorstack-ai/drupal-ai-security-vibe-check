<?php

/**
 * @file
 * Bootstrap file for unit tests.
 */

// Use the composer autoloader.
$autoloader = require __DIR__ . '/../vendor/autoload.php';

// Add the Drupal core tests namespaces.
$autoloader->addPsr4('Drupal\\Tests\\', __DIR__ . '/../vendor/drupal/core/tests/Drupal/Tests/');
$autoloader->addPsr4('Drupal\\TestTools\\', __DIR__ . '/../vendor/drupal/core/tests/Drupal/TestTools/');
