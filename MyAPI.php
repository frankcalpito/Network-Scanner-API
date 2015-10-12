<?php

require_once 'API.class.php';
require_once 'networkscanner.class.php';
// require 'vendor/willdurand/nmap/src/Nmap/Nmap.php';
require 'vendor/autoload.php';

class MyAPI extends API
{
    protected $User;

    protected $origin;

    protected $ip_add;

    protected $net_scanner;

    protected $loader;
    //changed parameters removed origin for testing
    public function __construct($request) {
        parent::__construct($request);


        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip_add = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip_add = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $ip_add = $_SERVER['REMOTE_ADDR'];
        }

        $this->ip_add = $ip_add;

        $this->origin = $origin;

        //test
        $this->net_scanner = new networkscanner($ip_add, 50550, 55555000);

    }

     protected function get_ip() {
        if ($this->method == 'GET') {
            return $this->ip_add;
        } else {
            return "Only accepts GET requests";
        }
     }

     protected function test2() {
        if ($this->method == 'GET') {

            return $this->args;
        }
     }

     protected function scan_net_ports() {
        
        if ($this->method == 'GET') {

            $output = (object) array();

            if($this->args == null)
                $output = $this->net_scanner->do_scan();
            elseif (empty($this->args[1])) 
                $output = $this->net_scanner->do_scan($this->args[0]);
            else
                $output = $this->net_scanner->do_scan($this->args[0], $this->args[1]);
            
            return $output;
        }
        else
            return "This method only accepts GET requests";
     }

    protected function scan_common_ports() {
        
        if ($this->method == 'GET') {

            $output = (object) array();

            $ports = array(21,22,23,25,53,80,110,115,135,139,143,194,443,445,1433,3306,3389,5632,5900);

            if($this->args == null)
                $output = $this->net_scanner->do_scan_common_ports($ports);
            else
                $output = "This method doesn't accept arguments";
            
            return $output;
        }
        else
            return "This method only accepts GET requests";
     }

     protected function scan_common_ports_2() {

        // using nmap lib by willdurand
        if ($this->method == 'GET') {

            $output = (object) array();

            //check if args is empty
            $ports = array(21,22,23,25,53,80,110,115,135,139,143,194,443,445,1433,3306,3389,5632,5900);

            if($this->args == null){
                $nmap = new Nmap\Nmap(null, __DIR__.'/output.xml');

                $nmap
                ->scan([ $this->ip_add ],[20,23,80]);
            }
            else
                $output = "This method doesn't accept arguments";
            
            return $output;
        }

        else
            return "This method only accepts GET requests";
        //  return json_encode("Origin: " . $this->origin . "| Ip address: " . $this->ip_add);
     }
 }