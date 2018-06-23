package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class DataflowTest {

   @Test
   public void testDataflow() {
	   
	   System.out.println("########## TESTS FOR DATAFLOW ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");
	   
	   NetworkService netServ = new NetworkService();
	   Dataflow dataflow = new Dataflow();
	   NetworkClient netClt = new NetworkClient();
	   
	   netServ.addDataflows(dataflow);
	   netClt.addDataflows(dataflow);
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(netServ.access);
	   attacker.addAttackPoint(netClt.access);
	   attacker.attack();
	   
	   netClt._softwareAccess.assertCompromisedInstantaneously();
	   dataflow.request.assertCompromisedInstantaneously();
	   netServ.connect.assertCompromisedInstantaneously();
	     
	   dataflow.denialOfService.assertCompromisedInstantaneously();
	   
	   netServ._softwareAccess.assertCompromisedInstantaneously();
	   dataflow.respond.assertCompromisedInstantaneously();
	   netClt.connect.assertCompromisedInstantaneously();
	   
	  
   }

	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


