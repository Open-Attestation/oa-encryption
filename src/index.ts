import { getLogger } from "./util/logger";

const { trace } = getLogger("sayHello");

/**
 * This function says hello.
 * @param name Some name to say hello for.
 * @returns The hello.
 */
const sayHello = (name: string = "Haz"): string => {
  trace("I'm working!");
  return `Hello, ${name}!`;
};

export default sayHello;
