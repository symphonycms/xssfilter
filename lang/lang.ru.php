<?php

	$about = array(
		'name' => 'Русский',
		'author' => array(
			'name' => 'Александр Бирюков',
			'email' => 'info@alexbirukov.ru',
			'website' => 'http://alexbirukov.ru'
		),
		'release-date' => '2012-06-16'
	);

	/**
	 * Cross-Site Scripting (XSS) Filter
	 */
	$dictionary = array(

		'Possible XSS attack detected in submitted data' => 
		'Возможно в полученных данных имеются следы XSS атаки',

	);
