<?php

	Class Extension_XSSFilter extends Extension {

		public function about() {
			return array(
				'name' => 'Cross-Site Scripting (XSS) Filter',
				'version' => '1.1',
				'release-date' => '2011-06-29',
				'author' => array(
					'name' => 'Symphony Team',
					'website' => 'http://symphony-cms.com/',
					'email' => 'team@symphony-cms.com'
				),
				'description' => 'Protect yourself against XSS attacks in form submissions.'
			);
		}

		public function getSubscribedDelegates() {
			return array(
				array(
					'page' => '/blueprints/events/new/',
					'delegate' => 'AppendEventFilter',
					'callback' => 'appendEventFilter'
				),
				array(
					'page' => '/blueprints/events/edit/',
					'delegate' => 'AppendEventFilter',
					'callback' => 'appendEventFilter'
				),
				array(
					'page' => '/frontend/',
					'delegate' => 'EventPreSaveFilter',
					'callback' => 'eventPreSaveFilter'
				),
			);
		}

		public function appendEventFilter(array $context) {
			$context['options'][] = array(
				'xss-fail',
				is_array($context['selected']) ? in_array('xss-fail', $context['selected']) : false,
				'Filter XSS: Fail if malicious input is detected'
			);
		}

		public function eventPreSaveFilter(array $context) {
			if(!in_array('xss-fail', $context['event']->eParamFILTERS) && !in_array('xss-remove', $context['event']->eParamFILTERS)) return;

			$contains_xss = FALSE;

			// Loop over the fields to check for XSS, this loop will
			// break as soon as XSS is detected
			foreach($context['fields'] as $field => $value) {
				if(is_array($value)) {
					if(self::detectXSSInArray($value) === FALSE) continue;

					$contains_xss = TRUE;
					break;
				}
				else {
					if(self::detectXSS($value) === FALSE) continue;

					$contains_xss = TRUE;
					break;
				}
			}

			// "fail" filter
			if(in_array('xss-fail', $context['event']->eParamFILTERS) && $contains_xss === TRUE) {
				$context['messages'][] = array(
					'xss', FALSE, __("Possible XSS attack detected in submitted data")
				);
			}
		}

		/**
		 * A utility function to manage nested array structures, checking
		 * each value for possible XSS. Function returns boolean if XSS is
		 * found.
		 *
		 * @param array $array
		 *  An array of data to check, this can be nested arrays.
		 * @return boolean
		 *  True if XSS is detected, false otherwise
		 */
		public static function detectXSSInArray(array $array) {
			foreach($array as $value) {
				if(is_array($value)) {
					return self::detectXSSInArray($value);
				}
				else {
					if(self::detectXSS($value) === TRUE) return TRUE;
				}
			}

			return FALSE;
		}

		/**
		 * Given a string, this function will determine if it potentially an
		 * XSS attack and return boolean.
		 *
		 * @param string $string
		 *  The string to run XSS detection logic on
		 * @return boolean
		 *  True if the given `$string` contains XSS, false otherwise.
		 */
		public static function detectXSS($string) {
			$contains_xss = FALSE;

			if(!is_string($string)) {
				throw new Exception(__('Passed parameter is not a string.'));
			}

			// Keep a copy of the original string before cleaning up
			$orig = $string;

			// URL decode
			$string = urldecode($string);

			// Convert Hexadecimals
			$string = preg_replace('!(&#|\\\)[xX]([0-9a-fA-F]+);?!e','chr(hexdec("$2"))', $string);

			// Clean up entities
			$string = preg_replace('!(&#0+[0-9]+)!','$1;',$string);

			// Decode entities
			$string = html_entity_decode($string, ENT_NOQUOTES, 'UTF-8');

			// Strip whitespace characters
			$string = preg_replace('!\s!','',$string);

			// Set the patterns we'll test against
			$patterns = array(
				// Match any attribute starting with "on" or xmlns
				'#(<[^>]+[\x00-\x20\"\'\/])(on|xmlns)[^>]*>?#iUu',

				// Match javascript:, livescript:, vbscript: and mocha: protocols
				'!((java|live|vb)script|mocha):(\w)*!iUu',
				'#-moz-binding[\x00-\x20]*:#u',

				// Match style attributes
				'#(<[^>]+[\x00-\x20\"\'\/])style=[^>]*>?#iUu',

				// Match unneeded tags
				'#</*(applet|meta|xml|blink|link|style|script|embed|object|iframe|frame|frameset|ilayer|layer|bgsound|title|base)[^>]*>?#i'
			);

			foreach($patterns as $pattern) {
				// Test both the original string and clean string
				if(preg_match($pattern, $string) || preg_match($pattern, $orig)){
					$contains_xss = TRUE;
				}
				if ($contains_xss === TRUE) return TRUE;
			}

			return FALSE;
		}

	}
