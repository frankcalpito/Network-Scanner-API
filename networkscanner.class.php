<?php

	// Scanner class to contain all method calls by api core
	// Network Scanner v1

	class NetworkScanner
	{

		protected $ip_add;

		function __construct($ip_add) {

			$this->ip_add = $ip_add;

		}

		function do_scan($start = null, $end = null) {
			
			$results = array();
			$ip = $this->ip_add;
			$wait = $this->wait; 
			$ctr = 0;

			if($start == null && $end == null) {
				$start = 20;
				$end = 25;	
			}

			if($start !== null && $end == null)
				$end = $start;

			for($port = $start; $port <= $end; $port++) {

	          if (!getservbyport($port,"tcp")) { $pname = ""; }
	          else { $pname = getservbyport($port,"tcp"); }
	          
	          $connection = @fsockopen($ip, $port);

			    if (is_resource($connection))
			    {
			        $status = "open";
			        fclose($connection);
			    }

			    else
			    {
			    	$status = "closed";
			    }

			  $results[$ctr] = array(
			  					"number" => (int) $port,
			  					"name"   => $pname,
			  					"status" => $status
			  				);

	          $ctr++;

	        }

			return $results;

		}

		function do_scan_common_ports($ports) {
			
			$results = array();
			$ip = $this->ip_add;
			$wait = $this->wait; 
			$ctr = 0;

			foreach($ports as $port) {

	          if (!getservbyport($port,"tcp")) { $pname = ""; }
	          else { $pname = getservbyport($port,"tcp"); }
	          
	          $connection = @fsockopen($ip, $port);

			    if (is_resource($connection))
			    {
			        $status = "open";
			        fclose($connection);
			    }

			    else
			    {
			    	$status = "closed";
			    }

			  $results[$ctr] = array(
			  					"number" => (int) $port,
			  					"name"   => $pname,
			  					"status" => $status
			  				);

	          $ctr++;

	        }

			return $results;

		}	

	}