// Stand-in for the real gateway client: only the shapes pc-fe-ts recognises.
export const GatewayEndpoint = {
	create<T>(cfg: T): T {
		return cfg;
	},
};

export const browser = false;

export function gql(strings: TemplateStringsArray, ...v: unknown[]): string {
	return String.raw({ raw: strings }, ...v);
}
