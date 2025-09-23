function assert(
	condition: unknown,
	message?: string | Error
): asserts condition {
	if (!condition) {
		if (message instanceof Error) throw message;
		throw new Error(message ?? "Assertion failed");
	}
}

assert.strictEqual = function (
	actual: unknown,
	expected: unknown,
	message?: string | Error
): void {
	if (actual !== expected) {
		if (message instanceof Error) throw message;
		throw new Error(
			message ?? `Expected ${expected}, but got ${actual} instead`
		);
	}
};

export default assert;
