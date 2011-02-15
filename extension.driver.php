<?php
	
	Class Extension_XSSFilter extends Extension {
	
		private $_is_xss = FALSE;

		public function about() {
			return array(
				'name' => 'Cross-Site Scripting (XSS) Filter',
				'version' => '1.0',
				'release-date' => '2010-10-08',
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
		
		public function appendEventFilter($context) {
			$context['options'][] = array(
				'xss-fail',
				@in_array('xss-fail', $context['selected']),
				'Filter XSS: Fail if malicious input is detected'
			);
		}
	
		public function eventPreSaveFilter($context) {
			if(!in_array('xss-fail', $context['event']->eParamFILTERS) && !in_array('xss-remove', $context['event']->eParamFILTERS)) return;
		
			foreach($context['fields'] as $field => $value) {
			
				if(is_array($value)) {
					foreach($value as $k => $v) {
						$value[$k] = $this->detectXSS($v);
					}
				} else {
					$value = $this->detectXSS($value);
				}
			}
		
			// "fail" filter
			if(in_array('xss-fail', $context['event']->eParamFILTERS) && $this->_is_xss === TRUE) {
				$context['messages'][] = array(
					'xss', FALSE, __("Possible XSS attack detected in submitted data")
				);
			}
		}
	
		private function detectXSS($string) {
		
			$contains_xss = FALSE;
			
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
				
				// Match javascript: and vbscript: protocols
				'!javascript:(\w)*!iUu',
				'!vbscript:!iUu',
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
				if ($contains_xss === TRUE) $this->_is_xss = $contains_xss;
			}
		}

}
