import { AuthClient, navigatorLock, User } from '@supabase/auth-js'
import { isBrowser } from './helpers'

export const STORAGE_KEY = process.env.NEXT_PUBLIC_STORAGE_KEY || 'supabase.dashboard.auth.token'
export const AUTH_DEBUG_KEY =
  process.env.NEXT_PUBLIC_AUTH_DEBUG_KEY || 'supabase.dashboard.auth.debug'
export const AUTH_DEBUG_PERSISTED_KEY =
  process.env.NEXT_PUBLIC_AUTH_DEBUG_PERSISTED_KEY || 'supabase.dashboard.auth.debug.persist'
export const AUTH_NAVIGATOR_LOCK_DISABLED_KEY =
  process.env.NEXT_PUBLIC_AUTH_NAVIGATOR_LOCK_KEY ||
  'supabase.dashboard.auth.navigatorLock.disabled'

/**
 * Catches errors thrown when accessing localStorage. Safari with certain
 * security settings throws when localStorage is accessed.
 */
function safeGetLocalStorage(key: string) {
  try {
    return globalThis?.localStorage?.getItem(key)
  } catch {
    return null
  }
}

const debug =
  process.env.NEXT_PUBLIC_IS_PLATFORM === 'true' && safeGetLocalStorage(AUTH_DEBUG_KEY) === 'true'

const persistedDebug =
  process.env.NEXT_PUBLIC_IS_PLATFORM === 'true' &&
  safeGetLocalStorage(AUTH_DEBUG_PERSISTED_KEY) === 'true'

const shouldEnableNavigatorLock =
  process.env.NEXT_PUBLIC_IS_PLATFORM === 'true' &&
  !(safeGetLocalStorage(AUTH_NAVIGATOR_LOCK_DISABLED_KEY) === 'true')

const shouldDetectSessionInUrl = process.env.NEXT_PUBLIC_AUTH_DETECT_SESSION_IN_URL
  ? process.env.NEXT_PUBLIC_AUTH_DETECT_SESSION_IN_URL === 'true'
  : true

const navigatorLockEnabled = !!(shouldEnableNavigatorLock && globalThis?.navigator?.locks)

if (isBrowser && shouldEnableNavigatorLock && !globalThis?.navigator?.locks) {
  console.warn('This browser does not support the Navigator Locks API. Please update it.')
}

const tabId = Math.random().toString(16).substring(2)

let dbHandle = new Promise<IDBDatabase | null>((accept, _) => {
  if (!persistedDebug) {
    accept(null)
    return
  }

  const request = indexedDB.open('auth-debug-log', 1)

  request.onupgradeneeded = (event: any) => {
    const db = event?.target?.result

    if (!db) {
      return
    }

    db.createObjectStore('events', { autoIncrement: true })
  }

  request.onsuccess = (event: any) => {
    console.log('Opened persisted auth debug log IndexedDB database', tabId)
    accept(event.target.result)
  }

  request.onerror = (event: any) => {
    console.error('Failed to open persisted auth debug log IndexedDB database', event)
    accept(null)
  }
})

const logIndexedDB = (message: string, ...args: any[]) => {
  console.log(message, ...args)

  const copyArgs = structuredClone(args)

  copyArgs.forEach((value) => {
    if (typeof value === 'object' && value !== null) {
      delete value.user
      delete value.access_token
      delete value.token_type
      delete value.provider_token
    }
  })
  ;(async () => {
    try {
      const db = await dbHandle

      if (!db) {
        return
      }

      const tx = db.transaction(['events'], 'readwrite')
      tx.onerror = (event: any) => {
        console.error('Failed to write to persisted auth debug log IndexedDB database', event)
        dbHandle = Promise.resolve(null)
      }

      const events = tx.objectStore('events')

      events.add({
        m: message.replace(/^GoTrueClient@/i, ''),
        a: copyArgs,
        l: window.location.pathname,
        t: tabId,
      })
    } catch (e: any) {
      console.error('Failed to log to persisted auth debug log IndexedDB database', e)
      dbHandle = Promise.resolve(null)
    }
  })()
}

/**
 * Reference to a function that captures exceptions for debugging purposes to be sent to Sentry.
 */
let captureException: ((e: any) => any) | null = null

export function setCaptureException(fn: typeof captureException) {
  captureException = fn
}

async function debuggableNavigatorLock<R>(
  name: string,
  acquireTimeout: number,
  fn: () => Promise<R>
): Promise<R> {
  let stackException: any

  try {
    throw new Error('Lock is being held for over 10s here')
  } catch (e: any) {
    stackException = e
  }

  const debugTimeout = setTimeout(() => {
    ;(async () => {
      const bc = new BroadcastChannel('who-is-holding-the-lock')
      try {
        bc.postMessage({})
      } finally {
        bc.close()
      }

      console.error(
        `Waited for over 10s to acquire an Auth client lock`,
        await navigator.locks.query(),
        stackException
      )
    })()
  }, 10000)

  try {
    return await navigatorLock(name, acquireTimeout, async () => {
      clearTimeout(debugTimeout)

      const bc = new BroadcastChannel('who-is-holding-the-lock')
      bc.addEventListener('message', () => {
        console.error('Lock is held here', stackException)

        if (captureException) {
          captureException(stackException)
        }
      })

      try {
        return await fn()
      } finally {
        bc.close()
      }
    })
  } catch (e: any) {
    // Circuit breaker for the steal-cascade deadlock (Issue #44642).
    //
    // When a Chrome tab is suspended, navigator.locks can become orphaned —
    // the lock is held at the browser level but the JS holding it is frozen.
    // auth-js recovers by using { steal: true }, but per the Web Locks spec
    // the original holder's fn() continues running as an orphaned task. When
    // it resumes and calls navigatorLock() again, auth-js detects that OUR
    // lock was stolen and throws NavigatorLockAcquireTimeoutError with the
    // "stole it" message. If we re-throw here, the caller gets an unhandled
    // error and any pending auth operations never complete — the app freezes.
    //
    // Fix: run fn() directly, without the lock. This is safe because at this
    // point we are already running as an orphaned background task (the lock
    // we held was stolen). Completing fn() harmlessly and exiting breaks the
    // infinite queue — the stealer already holds the lock and will complete
    // its own fn(), so the two runs are racing (bad), but no worse than the
    // status quo from auth-js's own steal recovery which also runs fn() twice.
    // Crucially, it prevents the infinite steal-back loop that freezes the UI.
    if (
      e?.name === 'NavigatorLockAcquireTimeoutError' ||
      (typeof e?.message === 'string' && e.message.includes('stole it'))
    ) {
      console.warn(
        '[Supabase Auth] Circuit breaker tripped: Lock cascade detected. ' +
          'Bypassing lock to unfreeze app. ' +
          `Lock name: "${name}". Original error: ${e?.message}`
      )

      if (captureException) {
        captureException(e)
      }

      return await fn()
    }

    throw e
  } finally {
    clearTimeout(debugTimeout)
  }
}

export const gotrueClient = new AuthClient({
  url: process.env.NEXT_PUBLIC_GOTRUE_URL,
  storageKey: STORAGE_KEY,
  detectSessionInUrl: shouldDetectSessionInUrl,
  debug: debug ? (persistedDebug ? logIndexedDB : true) : false,
  lock: navigatorLockEnabled ? debuggableNavigatorLock : undefined,
  ...('localStorage' in globalThis
    ? { storage: globalThis.localStorage, userStorage: globalThis.localStorage }
    : null),
})

export type { User }
