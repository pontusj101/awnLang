package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class InstanceTest {

   @Test
   public void testInstance_noDefenses() {
	   
	   System.out.println("########## TESTS FOR INSTANCE ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE ~~~~~");
	   
	   AccessKey key = new AccessKey();
	   Instance instance = new Instance();
	   IAMaccount iamacct = new IAMaccount();
	   
	   instance.addAccessKey(key);
	   iamacct.addAccessedInstances(instance);
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(instance.connect);
	   attacker.addAttackPoint(key.compromise);
	   attacker.addAttackPoint(iamacct.compromise);
	   attacker.attack();
	   
	   instance.keyaccess.assertCompromisedInstantaneously();
	   instance.attemptConnectBasicAWSProtection.assertCompromisedInstantaneously();
	   instance.authenticate.assertCompromisedInstantaneously();
	   instance.authenticatedAccess.assertCompromisedInstantaneously();
	   instance.access.assertCompromisedInstantaneously();
	   instance._machineAccess.assertCompromisedInstantaneously();
	   instance.denialOfService.assertCompromisedInstantaneously();
	   instance.compromisedAccess.assertCompromisedInstantaneously();
	  
   }
   
   @Test
   public void testInstance_allDefenses() {
	   
	   System.out.println("~~~~~ ALL DEFENSES IN PLACE ~~~~~");
	   
	   AccessKey key = new AccessKey();
	   Instance instance = new Instance(true, true);
	   
	   instance.addAccessKey(key);
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(instance.connect);
	   attacker.addAttackPoint(key.compromise);
	   attacker.attack();
	   
	   instance.keyaccess.assertCompromisedInstantaneously();
	   instance.attemptConnectAdvancedAWSProtection.assertCompromisedWithEffort();
	   instance.authenticate.assertCompromisedWithEffort();
	   instance.authenticatedAccess.assertCompromisedWithEffort();
	   instance.access.assertCompromisedWithEffort();
	   instance._machineAccess.assertCompromisedWithEffort();
	   instance.denialOfService.assertCompromisedWithEffort();
	  
   }

	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


