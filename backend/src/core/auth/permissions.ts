export enum Permission {
  DASHBOARD_VIEW = 'dashboard:view',
  DASHBOARD_ADMIN = 'dashboard:admin',

  PROJECT_CREATE = 'project:create',
  PROJECT_READ = 'project:read',
  PROJECT_UPDATE = 'project:update',
  PROJECT_DELETE = 'project:delete',

  SCAN_LAUNCH = 'scan:launch',
  SCAN_READ = 'scan:read',
  SCAN_CANCEL = 'scan:cancel',
  SCAN_DELETE = 'scan:delete',

  FINDING_READ = 'finding:read',
  FINDING_UPDATE = 'finding:update',
  FINDING_ASSIGN = 'finding:assign',
  FINDING_EXPORT = 'finding:export',

  REPORT_CREATE = 'report:create',
  REPORT_READ = 'report:read',
  REPORT_DELETE = 'report:delete',

  API_CLIENT_USE = 'api-client:use',
  API_CLIENT_MANAGE = 'api-client:manage',

  USER_CREATE = 'user:create',
  USER_READ = 'user:read',
  USER_UPDATE = 'user:update',
  USER_DELETE = 'user:delete',
  USER_DISABLE = 'user:disable',

  ORG_MANAGE = 'org:manage',
  TEAM_MANAGE = 'team:manage',

  INTEGRATION_MANAGE = 'integration:manage',
  INTEGRATION_VIEW = 'integration:view',

  SCHEDULER_MANAGE = 'scheduler:manage',
  SCHEDULER_VIEW = 'scheduler:view',

  SETTINGS_MANAGE = 'settings:manage',
  SETTINGS_VIEW = 'settings:view',

  AUDIT_LOG_VIEW = 'audit:view',

  SEARCH_GLOBAL = 'search:global',

  ADMIN_FULL = 'admin:full',
}

export enum Role {
  SUPER_ADMIN = 'super_admin',
  ADMIN = 'admin',
  SECURITY_LEAD = 'security_lead',
  SECURITY_ANALYST = 'security_analyst',
  DEVELOPER = 'developer',
  VIEWER = 'viewer',
  SERVICE_ACCOUNT = 'service_account',
}

export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  [Role.SUPER_ADMIN]: Object.values(Permission),

  [Role.ADMIN]: [
    Permission.DASHBOARD_VIEW,
    Permission.DASHBOARD_ADMIN,
    Permission.PROJECT_CREATE,
    Permission.PROJECT_READ,
    Permission.PROJECT_UPDATE,
    Permission.PROJECT_DELETE,
    Permission.SCAN_LAUNCH,
    Permission.SCAN_READ,
    Permission.SCAN_CANCEL,
    Permission.SCAN_DELETE,
    Permission.FINDING_READ,
    Permission.FINDING_UPDATE,
    Permission.FINDING_ASSIGN,
    Permission.FINDING_EXPORT,
    Permission.REPORT_CREATE,
    Permission.REPORT_READ,
    Permission.REPORT_DELETE,
    Permission.API_CLIENT_USE,
    Permission.API_CLIENT_MANAGE,
    Permission.USER_CREATE,
    Permission.USER_READ,
    Permission.USER_UPDATE,
    Permission.USER_DELETE,
    Permission.USER_DISABLE,
    Permission.ORG_MANAGE,
    Permission.TEAM_MANAGE,
    Permission.INTEGRATION_MANAGE,
    Permission.INTEGRATION_VIEW,
    Permission.SCHEDULER_MANAGE,
    Permission.SCHEDULER_VIEW,
    Permission.SETTINGS_MANAGE,
    Permission.SETTINGS_VIEW,
    Permission.AUDIT_LOG_VIEW,
    Permission.SEARCH_GLOBAL,
  ],

  [Role.SECURITY_LEAD]: [
    Permission.DASHBOARD_VIEW,
    Permission.PROJECT_CREATE,
    Permission.PROJECT_READ,
    Permission.PROJECT_UPDATE,
    Permission.SCAN_LAUNCH,
    Permission.SCAN_READ,
    Permission.SCAN_CANCEL,
    Permission.FINDING_READ,
    Permission.FINDING_UPDATE,
    Permission.FINDING_ASSIGN,
    Permission.FINDING_EXPORT,
    Permission.REPORT_CREATE,
    Permission.REPORT_READ,
    Permission.API_CLIENT_USE,
    Permission.USER_READ,
    Permission.INTEGRATION_MANAGE,
    Permission.INTEGRATION_VIEW,
    Permission.SCHEDULER_VIEW,
    Permission.SCHEDULER_MANAGE,
    Permission.SEARCH_GLOBAL,
  ],

  [Role.SECURITY_ANALYST]: [
    Permission.DASHBOARD_VIEW,
    Permission.PROJECT_READ,
    Permission.SCAN_LAUNCH,
    Permission.SCAN_READ,
    Permission.FINDING_READ,
    Permission.FINDING_UPDATE,
    Permission.REPORT_CREATE,
    Permission.REPORT_READ,
    Permission.API_CLIENT_USE,
    Permission.SEARCH_GLOBAL,
  ],

  [Role.DEVELOPER]: [
    Permission.DASHBOARD_VIEW,
    Permission.PROJECT_READ,
    Permission.SCAN_READ,
    Permission.FINDING_READ,
    Permission.REPORT_READ,
    Permission.SEARCH_GLOBAL,
  ],

  [Role.VIEWER]: [
    Permission.DASHBOARD_VIEW,
    Permission.PROJECT_READ,
    Permission.SCAN_READ,
    Permission.FINDING_READ,
    Permission.REPORT_READ,
  ],

  [Role.SERVICE_ACCOUNT]: [
    Permission.SCAN_LAUNCH,
    Permission.SCAN_READ,
    Permission.FINDING_READ,
    Permission.FINDING_EXPORT,
    Permission.REPORT_CREATE,
    Permission.REPORT_READ,
    Permission.API_CLIENT_USE,
  ],
};

export function hasPermission(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role]?.includes(permission) ?? false;
}

export function hasAllPermissions(role: Role, permissions: Permission[]): boolean {
  return permissions.every((p) => hasPermission(role, p));
}

export function hasAnyPermission(role: Role, permissions: Permission[]): boolean {
  return permissions.some((p) => hasPermission(role, p));
}
