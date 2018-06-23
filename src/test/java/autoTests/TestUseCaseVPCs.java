package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class TestUseCaseVPCs {
	
	/*
	 * 
	 * 		  AuthenticationService
	 * 					|
	 * 			    Credentials
	 *					| 
	 * 		User -> IAMaccount ----------------------
	 * 				 _______________________________|_______________________________
	 * 				|												  				|
	 * 					Instance <-> Network <-> Gateway <-> Network <-> Instance			
	 * 
	 * 
	 * 		User has an IAM account that they use to control a VPC (two subnets connected to each other via a gateway).
	 * 
	 * 		(All defenses in place. Not shown in figure.)
	 * 		
	 * 		Attacker is able to compromise the user's IAM account. This should lead to complete control over the various
	 * 		components of the VPC: the subnets, the gateways, the dataflows, etc. However, the attacker should only be 
	 * 		able to connect to the instances and not have access to them.
	 * 
	 */

   @Test
   public void testvpcsiamcompromise() {
	   
	  System.out.println("########## USE CASE TESTS FOR VPCs ##########");
	  
	  User user = new User("user", true);														// user is security aware
	  IAMaccount iam = new IAMaccount("iam");
	  Credentials cred = new Credentials("namepass");
	  AuthenticationService authServ = new AuthenticationService("authServ", false, true);		// authentication service is firewall protected and patch up-to-date
	  Network sub1 = new Network("subnet1");
	  Network sub2 = new Network("subnet2");
	  Gateway gateway = new Gateway("gateway");
	  Instance instance1 = new Instance("instance1");
	  Instance instance2 = new Instance("instance2");
	  
	  user.addAccounts(iam);
	  iam.addCredentials(cred);
	  authServ.addAuthenticatedAccounts(iam);
	  iam.addNetworks(sub1);						//
	  iam.addNetworks(sub2);						//	IAM accounts can create and manage subnets and gateways
	  iam.addTrafficGateways(gateway);				//
	  iam.addAccessedInstances(instance1);
	  iam.addAccessedInstances(instance2);
	  gateway.addTrafficNetworks(sub1);
	  gateway.addTrafficNetworks(sub2);
	  sub1.addMachines(instance1);
	  sub2.addMachines(instance2);
	  
	  Attacker attacker = new Attacker();
      attacker.addAttackPoint(iam.compromise);
      attacker.attack();
      
      sub1.compromisedAccess.assertCompromisedInstantaneously();
      sub1._access.assertCompromisedInstantaneously();
      sub1.denialOfService.assertCompromisedInstantaneously();
      gateway.compromisedAccess.assertCompromisedInstantaneously();
      gateway.createNewConnections.assertCompromisedInstantaneously();
      instance1.connect.assertCompromisedInstantaneously();
      instance1.access.assertUncompromised();
      sub2.compromisedAccess.assertCompromisedInstantaneously();
      sub2._access.assertCompromisedInstantaneously();
      sub2.denialOfService.assertCompromisedInstantaneously();
      instance2.connect.assertCompromisedInstantaneously();
      instance2.access.assertUncompromised();
      
      }
   
   @After
   public void deleteModel() {
           Asset.allAssets.clear();
           AttackStep.allAttackSteps.clear();
           Defense.allDefenses.clear();
   }
}
