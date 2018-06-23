package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class IAMaccountTest {

   @Test
   public void testIAMaccount() {
	   
	   System.out.println("########## TESTS FOR IAM ACCOUNT ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");
	   
	   IAMaccount iamacct = new IAMaccount();
	   Instance instance = new Instance();
	   Bucket bucket = new Bucket();
	   Group group = new Group();
	   Role role = new Role();
	   Network network = new Network();
	   Gateway gateway = new Gateway();
	   SecurityGroup secGrp = new SecurityGroup();
	   
	   iamacct.addAccessedInstances(instance);
	   iamacct.addAccessedBuckets(bucket);
	   iamacct.addCreatedIAMgroups(group);
	   iamacct.addGroups(group);
	   iamacct.addRole(role);
	   iamacct.addNetworks(network);
	   iamacct.addTrafficGateways(gateway);
	   iamacct.addSecurityGroup(secGrp);
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(iamacct.compromise);
	   attacker.attack();
	   
	   iamacct.compromisedAccess.assertCompromisedInstantaneously();
	   instance.compromisedAccess.assertCompromisedInstantaneously();
	   instance.denialOfService.assertCompromisedInstantaneously();
	   bucket.compromisedAccess.assertCompromisedInstantaneously();
	   bucket.access.assertCompromisedInstantaneously();
	   group.compromisedAccess.assertCompromisedInstantaneously();   
	   role.compromisedAccess.assertCompromisedInstantaneously();
	   network.compromisedAccess.assertCompromisedInstantaneously();
	   gateway.compromisedAccess.assertCompromisedInstantaneously();
	   secGrp.compromisedAccess.assertCompromisedInstantaneously();
	   
   }   

	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


