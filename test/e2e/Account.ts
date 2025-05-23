import { expect } from "chai";
import { ethers } from "hardhat";
import { EventLog } from "ethers";

import { TestAccount, TestAccountTarget } from "../../typechain-types";

describe('Account', () => {
    let contract : TestAccount;
    let target : TestAccountTarget;
    let cloneAddr : string;

    before(async () => {
        // Deploy AccountFactory implementation and proxy
        const accountFactoryFactory = await ethers.getContractFactory("AccountFactory");
        const accountFactoryProxyFactory = await ethers.getContractFactory("AccountFactoryProxy");
        const accountFactoryImpl = await accountFactoryFactory.deploy();
        await accountFactoryImpl.waitForDeployment();


        const AFProxy = await accountFactoryProxyFactory.deploy(
            await accountFactoryImpl.getAddress(),
            accountFactoryFactory.interface.encodeFunctionData('initialize', []),
        );
        await AFProxy.waitForDeployment();

        // Test Account factory
        let factory = await ethers.getContractFactory("TestAccount");
        contract = await factory.deploy(await AFProxy.getAddress());
        await contract.waitForDeployment();

        // Create target contract
        let factory2 = await ethers.getContractFactory('TestAccountTarget');
        target = await factory2.deploy();
        await target.waitForDeployment();

        // Create a cloned Account contact
        const firstSigner = (await ethers.getSigners())[0];
        const ctx = await contract.testClone(await firstSigner.getAddress());
        const cr = await ctx.wait();

        // Emits cloned contract address
        expect(cr?.logs.length).eq(2);
        const cl = (cr?.logs[1] as EventLog);
        cloneAddr = cl.args[0];
        expect(cloneAddr.length == 42);
    });

    it.skip('Account Staticcall Works', async () => {
        const acct = await ethers.getContractAt("AccountEVM", cloneAddr);
        const firstSigner = (await ethers.getSigners())[0];
        const acctWithSigner = acct.connect(firstSigner);

        // Verify controller status
        const isController = await acct.isController(await firstSigner.getAddress());
        expect(isController).to.be.true;

        // Encode public view call
        const example = target.interface.encodeFunctionData('exampleView');
        const example_result = await acctWithSigner.staticcall(await target.getAddress(), example);

        // Decode staticcall result
        const result = target.interface.decodeFunctionResult("exampleView", example_result);
        expect(result[0]).equal(await acct.getAddress());
        expect(result[1]).equal(await target.getAddress());
    });


    it('Account Modifier Works', async () => {
        const acct = await ethers.getContractAt("AccountEVM", cloneAddr);
        const acctWithSigner = acct.connect((await ethers.getSigners())[0]);

        expect(await acct.isController((await ethers.getSigners())[1].getAddress())).equal(false);
        await acctWithSigner.modifyController((await ethers.getSigners())[1].getAddress(), true);
        expect(await acct.isController((await ethers.getSigners())[1].getAddress())).equal(true);

        expect(await acctWithSigner.modifyController(ethers.ZeroAddress, true)).to.be.revertedWith("Invalid address");
    });

});
