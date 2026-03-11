import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed...');

  // Create 7 sample users
  const users = await Promise.all([
    prisma.user.upsert({
      where: { email: 'alice@example.com' },
      update: {},
      create: {
        email: 'alice@example.com',
        name: 'Alice Johnson',
      },
    }),
    prisma.user.upsert({
      where: { email: 'bob@example.com' },
      update: {},
      create: {
        email: 'bob@example.com',
        name: 'Bob Smith',
      },
    }),
    prisma.user.upsert({
      where: { email: 'carol@example.com' },
      update: {},
      create: {
        email: 'carol@example.com',
        name: 'Carol Davis',
      },
    }),
    prisma.user.upsert({
      where: { email: 'dave@example.com' },
      update: {},
      create: {
        email: 'dave@example.com',
        name: 'Dave Wilson',
      },
    }),
    prisma.user.upsert({
      where: { email: 'eve@example.com' },
      update: {},
      create: {
        email: 'eve@example.com',
        name: 'Eve Martinez',
      },
    }),
    prisma.user.upsert({
      where: { email: 'frank@example.com' },
      update: {},
      create: {
        email: 'frank@example.com',
        name: 'Frank Anderson',
      },
    }),
    prisma.user.upsert({
      where: { email: 'grace@example.com' },
      update: {},
      create: {
        email: 'grace@example.com',
        name: 'Grace Lee',
      },
    }),
  ]);

  console.log(`✅ Created/verified ${users.length} users`);

  // Create a shared project for all users (using the first user)
  const sharedProject = await prisma.project.upsert({
    where: { id: 'demo-project-001' },
    update: {},
    create: {
      id: 'demo-project-001',
      userId: users[0].id,
      name: 'Demo Project - example.com',
      description: 'Shared demonstration project for testing RedAmon reconnaissance',
      targetDomain: 'example.com',
      subdomainList: ['www', 'api', 'mail', 'staging'],
      ipMode: false,
      stealthMode: false,
      scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
      updateGraphDb: true,
      useBruteforceForSubdomains: true,
      naabuTopPorts: '1000',
      httpxThreads: 50,
    },
  });

  console.log(`✅ Created/verified shared project: ${sharedProject.name}`);

  // Create individual projects for each user
  const projects = await Promise.all(
    users.map((user, index) =>
      prisma.project.upsert({
        where: { id: `project-${index + 1}` },
        update: {},
        create: {
          id: `project-${index + 1}`,
          userId: user.id,
          name: `${user.name}'s Project`,
          description: `Personal reconnaissance project for ${user.name}`,
          targetDomain: `target${index + 1}.local`,
          subdomainList: ['www', 'api'],
          stealthMode: false,
          scanModules: ['domain_discovery', 'port_scan', 'http_probe'],
          updateGraphDb: true,
        },
      })
    )
  );

  console.log(`✅ Created ${projects.length} personal projects`);

  console.log('\n📊 Database seed complete!');
  console.log(`\n👥 Users created:`);
  users.forEach((user) => {
    console.log(`   • ${user.name} (${user.email})`);
  });
  console.log(`\n📁 Projects created:`);
  console.log(`   • ${sharedProject.name} (shared)`);
  projects.forEach((project) => {
    console.log(`   • ${project.name}`);
  });
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
