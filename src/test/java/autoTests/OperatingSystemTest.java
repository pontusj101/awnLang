package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class OperatingSystemTest {

   @Test
   public void testOperatingSystem() {
	   
	   System.out.println("########## TESTS FOR OPERATING SYSTEM ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");		
	   												//	'OperatinSystem' asset does have a defense called 'insecureCustomAMIs', that relates to 'Vulnerability', which is unexplored as of yet
	   
	   AccessKey key = new AccessKey();
	   Instance instance = new Instance();
	   OperatingSystem operatingSystem = new OperatingSystem();
	   Account OSacct = new Account();
	   Application application = new Application();
	   	   
	   key.addAssignedInstances(instance);		
	   key.addAssignedOSaccount(OSacct);
	   instance.addExecutees(operatingSystem);
	   operatingSystem.addAssignedAccounts(OSacct);
	   operatingSystem.addExecutees(application);
		   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(instance.connect);
	   attacker.addAttackPoint(key.compromise);
	   attacker.attack();
	   
	   instance.keyaccess.assertCompromisedInstantaneously();
	   instance.attemptConnectBasicAWSProtection.assertCompromisedInstantaneously();
	   instance.authenticate.assertCompromisedInstantaneously();
	   instance.authenticatedAccess.assertCompromisedInstantaneously();
	   instance.access.assertCompromisedInstantaneously();
	   instance._machineAccess.assertCompromisedInstantaneously();
	   operatingSystem.connect.assertCompromisedInstantaneously();
	   operatingSystem.authenticate.assertCompromisedInstantaneously();
	   operatingSystem.authenticatedAccess.assertCompromisedInstantaneously();
	   operatingSystem.access.assertCompromisedInstantaneously();
	   operatingSystem._softwareAccess.assertCompromisedInstantaneously();
	   application.connect.assertCompromisedInstantaneously();
	  
   }
   
	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


