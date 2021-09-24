/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Gitpod. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

/// <reference path='../../../src/vs/vscode.d.ts'/>

import ClientOAuth2 from 'client-oauth2';
import crypto from 'crypto';
import * as vscode from 'vscode';
import { URLSearchParams, URL } from 'url';

import { GitpodClient, GitpodServer, GitpodServiceImpl } from '@gitpod/gitpod-protocol/lib/gitpod-service';
import { JsonRpcProxyFactory } from '@gitpod/gitpod-protocol/lib/messaging/proxy-factory';
import WebSocket = require('ws');
import ReconnectingWebSocket from 'reconnecting-websocket';
import { ConsoleLogger, listen as doListen } from 'vscode-ws-jsonrpc';

const authCompletePath = '/auth-complete';
const baseURL = 'https://server-vscode-ouath2.staging.gitpod-dev.com';

export const scopes: string[] = [
	'function:accessCodeSyncStorage'
];

type UsedGitpodFunction = ['getWorkspace', 'openPort', 'stopWorkspace', 'setWorkspaceTimeout', 'getWorkspaceTimeout', 'getLoggedInUser', 'takeSnapshot', 'controlAdmission', 'sendHeartBeat', 'trackEvent'];
type Union<Tuple extends any[], Union = never> = Tuple[number] | Union;
export type GitpodConnection = Omit<GitpodServiceImpl<GitpodClient, GitpodServer>, 'server'> & {
	server: Pick<GitpodServer, Union<UsedGitpodFunction>>
};

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
function promiseFromEvent<T, U>(
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

/**
	Generates a code verifier and code challenge for the OAuth2 flow.
	@returns a tuple of the code verifier and code challenge
*/
function generatePKCE(): { codeVerifier: string, codeChallenge: string } {
	const codeVerifier = crypto.randomBytes(32).toString('base64');
	const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64');
	return { codeVerifier, codeChallenge };
}

/**
 * Returns a promise that resolves with the current authentication session of the provided access token. This includes the token itself, the scopes, the user's ID and name.
 * @param accessToken the access token used to authenticate the Gitpod WS connection
 * @param scopes the scopes the authentication session must have
 * @returns a promise that resolves with the authentication session
 */
export async function resolveAuthenticationSession(scopes: readonly string[], accessToken: string): Promise<vscode.AuthenticationSession> {
	const factory = new JsonRpcProxyFactory<GitpodServer>();
	const gitpodService: GitpodConnection = new GitpodServiceImpl<GitpodClient, GitpodServer>(factory.createProxy()) as any;

	const pendignWebSocket = (async () => {
		class GitpodServerWebSocket extends WebSocket {
			constructor(address: string, protocols?: string | string[]) {
				super(address, protocols, {
					headers: {
						'Origin': baseURL,
						'Authorization': `Bearer ${accessToken}`
					}
				});
			}
		}
		const webSocket = new ReconnectingWebSocket(baseURL.replace('https', 'wss'), undefined, {
			maxReconnectionDelay: 10000,
			minReconnectionDelay: 1000,
			reconnectionDelayGrowFactor: 1.3,
			connectionTimeout: 10000,
			maxRetries: Infinity,
			debug: false,
			startClosed: false,
			WebSocket: GitpodServerWebSocket
		});
		webSocket.onerror = console.error;
		doListen({
			webSocket,
			onConnection: connection => factory.listen(connection),
			logger: new ConsoleLogger()
		});
		return webSocket;
	})();
	const user = await gitpodService.server.getLoggedInUser();
	(await pendignWebSocket).close();
	return {
		id: 'gitpod.user',
		account: {
			label: user.name!,
			id: user.id
		},
		scopes: scopes,
		accessToken: accessToken
	};
}

function hasScopes(session: vscode.AuthenticationSession, scopes?: readonly string[]): boolean {
	return !scopes || scopes.every(scope => session.scopes.includes(scope));
}

function registerAuth(context: vscode.ExtensionContext, logger: any): void {

	/**
	 * Returns a promise which waits until the secret store `gitpod.authSession` item changes.
	 * @returns a promise that resolves with the authentication session
	 */
	const waitForAuthenticationSession = async (): Promise<vscode.AuthenticationSession> => {
		logger('Waiting for the onchange event');

		// Wait until a session is added to the context's secret store
		const authPromise = promiseFromEvent(context.secrets.onDidChange, (changeEvent: vscode.SecretStorageChangeEvent, resolve, reject): void => {
			if (changeEvent.key !== 'gitpod.authSession') {
				reject('Cancelled');
			} else {
				resolve(changeEvent.key);
			}
		});
		const data = await authPromise.promise;

		logger(data);

		logger('Retrieving the session');

		const session: vscode.AuthenticationSession = JSON.parse(await context.secrets.get('gitpod.authSession') || '');
		return session;
	};

	async function createSession(_scopes: string[]): Promise<vscode.AuthenticationSession> {
		logger('Creating session...');

		const callbackUri = `${vscode.env.uriScheme}://gitpod.gitpod-desktop${authCompletePath}`;

		const gitpodAuth = new ClientOAuth2({
			clientId: 'vscode',
			accessTokenUri: `${baseURL}/api/oauth/token`,
			authorizationUri: `${baseURL}/api/oauth/authorize`,
			redirectUri: callbackUri,
			scopes: scopes,
		});

		const redirectUri = new URL(gitpodAuth.code.getUri());
		const secureQuery = new URLSearchParams(redirectUri.search);

		const codePair = generatePKCE();
		secureQuery.set('code_challenge', codePair.codeChallenge);
		secureQuery.set('code_challenge_method', 'S256');

		redirectUri.search = secureQuery.toString();

		const timeoutPromise = new Promise((_: (value: vscode.AuthenticationSession) => void, reject): void => {
			const wait = setTimeout(() => {
				clearTimeout(wait);
				reject('Login timed out.');
			}, 1000 * 60 * 5); // 5 minutes
		});

		// Open the authorization URL in the default browser
		const authURI = vscode.Uri.parse(redirectUri.toString());
		logger(`Opening browser at ${redirectUri.toString()}`);
		await vscode.env.openExternal(authURI);
		// @ts-ignore
		return Promise.race([timeoutPromise, waitForAuthenticationSession]);
	}

	//#endregion

	//#region gitpod auth
	const onDidChangeSessionsEmitter = new vscode.EventEmitter<vscode.AuthenticationProviderAuthenticationSessionsChangeEvent>();
	logger('Registering authentication provider...');
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
			logger('Pushing change emitter');
			context.subscriptions.push(onDidChangeSessionsEmitter);
			logger('Returning create ');
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
