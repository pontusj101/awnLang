package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class AccessKeyTest {

   @Test
   public void testAccessKey() {
	   
	   System.out.println("########## TESTS FOR ACCESS KEY ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");
	   
	   AccessKey key = new AccessKey();
	   Instance instance = new Instance();
	   IAMaccount iamacct = new IAMaccount();
	   
	   instance.addAccessKey(key);
	   iamacct.addAccessedInstances(instance);
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(instance.connect);
	   attacker.addAttackPoint(key.modifyKeyFile);
	   attacker.attack();
	   
	   key.modifyKeyFile.assertCompromisedInstantaneously();
	   key.compromise.assertCompromisedWithEffort();
	   instance.connect.assertCompromisedInstantaneously();
	   instance.access.assertCompromisedWithEffort();
	   
   }

	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


