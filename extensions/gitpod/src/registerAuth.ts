/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Gitpod. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

/// <reference path='../../../src/vs/vscode.d.ts'/>

import ClientOAuth2 from 'client-oauth2';
import * as vscode from 'vscode';

const authCompletePath = '/auth-complete';
const scopes: string[] = [
	'function:accessCodeSyncStorage'
];

function registerAuth(context: vscode.ExtensionContext): void {
	async function resolveAuthenticationSession(accessToken: string): Promise<vscode.AuthenticationSession> {
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
		return Promise.race([timeoutPromise, resolveAuthenticationSession('token')]);
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
