import { Lazy, Names } from 'aws-cdk-lib';
import { CfnIPSet, CfnWebACL } from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';

export interface CommonWebAclProps {
  readonly scope: 'REGIONAL' | 'CLOUDFRONT';
  readonly allowedIpV4AddressRanges?: string[] | null;
  readonly allowedIpV6AddressRanges?: string[] | null;
  readonly allowedCountryCodes?: string[] | null;
}

export class CommonWebAcl extends Construct {
  public readonly webAclArn: string;

  constructor(scope: Construct, id: string, props: CommonWebAclProps) {
    super(scope, id);

    const commonBlockRulePropreties = (name: string) => ({
      name,
      action: { block: {} },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: name,
      },
    });

    const suffix = Lazy.string({ produce: () => Names.uniqueId(this) });
    const blockRules: CfnWebACL.RuleProperty[] = [];

    if (
      props.allowedIpV4AddressRanges != null ||
      props.allowedIpV6AddressRanges != null
    ) {
      const wafIPv4Set = new CfnIPSet(this, `IPv4Set${id}`, {
        ipAddressVersion: 'IPV4',
        scope: props.scope,
        addresses:
          props.allowedIpV4AddressRanges == null
            ? ['0.0.0.0/1', '128.0.0.0/1']
            : props.allowedIpV4AddressRanges,
      });
      const wafIPv6Set = new CfnIPSet(this, `IPv6Set${id}`, {
        ipAddressVersion: 'IPV6',
        scope: props.scope,
        addresses:
          props.allowedIpV6AddressRanges == null
            ? ['::/1', '8000::/1']
            : props.allowedIpV6AddressRanges,
      });
      blockRules.push({
        ...commonBlockRulePropreties(`IpSetRule${id}`),
        priority: 1,
        // Block if not (in the IPv4 set or in the IPv6 set)
        statement: {
          notStatement: {
            statement: {
              orStatement: {
                statements: [
                  { ipSetReferenceStatement: { arn: wafIPv4Set.attrArn } },
                  { ipSetReferenceStatement: { arn: wafIPv6Set.attrArn } },
                ],
              },
            },
          },
        },
      });
    }

    if (props.allowedCountryCodes != null) {
      blockRules.push({
        ...commonBlockRulePropreties(`CountryCodeRule${id}`),
        priority: 2,
        // Block if not in the allowed country codes
        statement: {
          notStatement: {
            statement: {
              geoMatchStatement: { countryCodes: props.allowedCountryCodes },
            },
          },
        },
      });
    }

    const webAcl = new CfnWebACL(this, `WebAcl${id}`, {
      defaultAction: { allow: {} },
      name: `WebAcl-${suffix}`,
      scope: props.scope,
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        sampledRequestsEnabled: true,
        metricName: `WebAcl-${suffix}`,
      },
      rules: blockRules,
    });
    this.webAclArn = webAcl.attrArn;
  }
}
