/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Gitpod. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

/// <reference path='../../../src/vs/vscode.d.ts'/>

import ClientOAuth2 from 'client-oauth2';
import * as vscode from 'vscode';
import { URLSearchParams } from 'url';

const authCompletePath = '/auth-complete';

/*
const scopes: string[] = [
	'function:accessCodeSyncStorage'
];
*/

class UriEventHandler extends vscode.EventEmitter<vscode.Uri> implements vscode.UriHandler {
	constructor(private readonly Logger: any) {
		super();
	}

	public handleUri(uri: vscode.Uri) {
		this.Logger('Handling URI...');
		this.fire(uri);
	}
}

export interface PromiseAdapter<T, U> {
	(
		value: T,
		resolve:
			(value: U | PromiseLike<U>) => void,
		reject:
			(reason: any) => void
	): any;
}

const passthrough = (value: any, resolve: (value?: any) => void) => resolve(value);

/**
 * Return a promise that resolves with the next emitted event, or with some future
 * event as decided by an adapter.
 *
 * If specified, the adapter is a function that will be called with
 * `(event, resolve, reject)`. It will be called once per event until it resolves or
 * rejects.
 *
 * The default adapter is the passthrough function `(value, resolve) => resolve(value)`.
 *
 * @param event the event
 * @param adapter controls resolution of the returned promise
 * @returns a promise that resolves or rejects as specified by the adapter
 */
export function promiseFromEvent<T, U>(
	event: vscode.Event<T>,
	adapter: PromiseAdapter<T, U> = passthrough): { promise: Promise<U>, cancel: vscode.EventEmitter<void> } {
	let subscription: vscode.Disposable;
	let cancel = new vscode.EventEmitter<void>();
	return {
		promise: new Promise<U>((resolve, reject) => {
			cancel.event(_ => reject());
			subscription = event((value: T) => {
				try {
					Promise.resolve(adapter(value, resolve, reject))
						.catch(reject);
				} catch (error) {
					reject(error);
				}
			});
		}).then(
			(result: U) => {
				subscription.dispose();
				return result;
			},
			error => {
				subscription.dispose();
				throw error;
			}
		),
		cancel
	};
}

function registerAuth(context: vscode.ExtensionContext, logger: any): void {

	const uriHandler = new UriEventHandler(logger);
	vscode.window.registerUriHandler(uriHandler);

	const getToken: (scopes: string[]) => PromiseAdapter<vscode.Uri, string> = () => async (uri, resolve, reject) => {
		if (uri.path === authCompletePath) {
			// Get the token from the URI
			const token = new URLSearchParams(uri.query).get('token');
			if (token !== null) {
				// Store the token
				await context.secrets.store('gitpod.token', token);
				resolve(token);
			} else {
				reject('Auth failed: missing token');
			}
			return;
		}
	};

	async function resolveAuthenticationSession(scopes: readonly string[], accessToken: string): Promise<vscode.AuthenticationSession> {
		// Todo: use a real authentication session with @gitpod/protocol
		return {
			id: 'gitpod.user',
			account: {
				label: 'GitPod User',
				id: 'gitpod.user'
			},
			scopes: scopes,
			accessToken: accessToken
		};
	}

	function hasScopes(session: vscode.AuthenticationSession, scopes?: readonly string[]): boolean {
		return !scopes || scopes.every(scope => session.scopes.includes(scope));
	}

	async function createSession(scopes: string[]): Promise<vscode.AuthenticationSession> {
		const baseURL = 'https://server-vscode-ouath2.staging.gitpod-dev.com';

		const callbackUri = `${vscode.env.uriScheme}://gitpod.gitpod-desktop${authCompletePath}`;

		const gitpodAuth = new ClientOAuth2({
			clientId: 'vscode',
			accessTokenUri: `${baseURL}/api/oauth/token`,
			authorizationUri: `${baseURL}/api/oauth/authorize`,
			redirectUri: callbackUri,
			scopes: scopes,
		});

		const timeoutPromise = new Promise((_: (value: vscode.AuthenticationSession) => void, reject) => {
			const wait = setTimeout(() => {
				clearTimeout(wait);
				reject('Login timed out.');
			}, 1000 * 60 * 5); // 5 minutes
		});

		// Open the authorization URL in the default browser
		const authURI = vscode.Uri.parse(gitpodAuth.code.getUri());
		await vscode.env.openExternal(authURI);
		const authPromise = promiseFromEvent(uriHandler.event, getToken(scopes));
		return Promise.race([timeoutPromise, resolveAuthenticationSession(scopes, 'token')]);
	}

	//#endregion

	//#region gitpod auth
	const onDidChangeSessionsEmitter = new vscode.EventEmitter<vscode.AuthenticationProviderAuthenticationSessionsChangeEvent>();

	context.subscriptions.push(vscode.authentication.registerAuthenticationProvider('gitpod', 'Gitpod', {
		onDidChangeSessions: onDidChangeSessionsEmitter.event,
		getSessions: (scopes: string[]) => {
			const sessions: vscode.AuthenticationSession[] = [];
			if (!scopes) {
				return Promise.resolve(sessions);
			}
			return Promise.resolve(sessions.filter(session => hasScopes(session, scopes)));
		},
		createSession: async (scopes: string[]) => {
			context.subscriptions.push(onDidChangeSessionsEmitter);
			return createSession(scopes);
		},
		removeSession: async () => {
			// Todo: implement logging out
			throw new Error('not supported');
		},
	}, { supportsMultipleAccounts: false }));
	//#endregion gitpod auth
}

export { authCompletePath, registerAuth };
