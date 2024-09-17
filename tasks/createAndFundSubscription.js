const {SubscriptionManager} = require("@chainlink/functions-toolkit");
const {utils} = require("ethers");

const NETWORK = "optimismSepolia";
const linkTokenAddress = "0xE4aB69C077896252FAFBD49EFD26B5D171A32410"
const functionsRouterAddress = "0xC17094E3A1348E5C7544D4fF8A36c28f2C6AAE28";
const consumerAddress = "0xe39458fD1B6c29d7991e45d45e6112C412a8A593";
const LINK = "10";

const createAndFundSub = async() => {
    const subscriptionManager = new SubscriptionManager({
      signer,
      linkTokenAddress,
      functionsRouterAddress,
    })
    await subscriptionManager.initialize()

    const subscriptionId = await subscriptionManager.createSubscription()
    console.log("subscription id created at : ${subscriptionId}");

    const addConsumerTxReceipt = await subscriptionManager.addConsumer({
      subscriptionId,
      consumerAddress,
    })
    console.log("Subscription id : ${subscriptionId} has now consumer ${consumerAddress}")

    const juelsAmount = utils.parseUnits(LINK, 18);
    await subscriptionManager.fundSubscription({
      subscriptionId,
      juelsAmount,
    })

    console.log("SubscriptionId ${subscriptionId} is now funded with ${LINK} LINK Tokens");
}

createAndFundSub().catch(err => {
    console.log("error in creating or funding subscription");
})